//! Run ownership, paced launches, draining and CPU attribution.
use super::{
    call,
    endpoint::{Counters, Endpoint},
    media::Media,
    registration,
    report::{Percentiles, Summary},
    Error, RunPlan,
};
use crate::cpu;
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;
use tokio::{task::JoinSet, time::Instant};

/// A named controlling thread includes the runtime's block_on work in CPU attribution.
pub fn run(plan: RunPlan) -> Result<Summary, Error> {
    plan.validate()?;
    std::thread::Builder::new()
        .name("sipload-main".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(plan.sip_threads)
                .thread_name("sipload-sip")
                .enable_all()
                .build()?;
            runtime.block_on(execute(plan))
        })?
        .join()
        .map_err(|_| Error::Worker)?
}
async fn execute(plan: RunPlan) -> Result<Summary, Error> {
    let plan = Arc::new(plan);
    let counters = Arc::new(Counters::default());
    let media = Arc::new(Media::new(
        plan.local,
        plan.media_base_port,
        plan.media_sockets,
        plan.ptime,
        plan.media_threads,
    )?);
    let (stop_sender, stop_receiver) = tokio::sync::watch::channel(false);
    let mut dispatchers = JoinSet::new();
    let mut servers = Vec::new();
    for user in 1..=plan.users {
        let endpoint = Endpoint::bind(
            (plan.local, plan.uas_base_port + user as u16).into(),
            counters.clone(),
        )
        .await?;
        dispatchers.spawn(
            endpoint
                .clone()
                .dispatch(Some((plan.clone(), media.clone())), stop_receiver.clone()),
        );
        servers.push(endpoint);
    }
    if !plan.skip_registration {
        for (index, endpoint) in servers.iter().enumerate() {
            registration::register(endpoint, &plan, index + 1)
                .await
                .map_err(|error| {
                    Error::Registration(format!("bob{}", index + 1), error.to_string())
                })?;
        }
    }
    let mut clients = Vec::new();
    for _ in 0..plan.uac_sockets {
        let endpoint = Endpoint::bind((plan.local, 0).into(), counters.clone()).await?;
        dispatchers.spawn(endpoint.clone().dispatch(None, stop_receiver.clone()));
        clients.push(endpoint);
    }
    let baseline = cpu::sample();
    let start = Instant::now();
    let mut summary = Summary::default();
    let mut calls = JoinSet::new();
    let total = plan.calls();
    let mut pacer = super::pacing::Pacer::new(total, plan.cps)?;
    while summary.attempted < total || !calls.is_empty() {
        tokio::select! {
            biased;
            Some(result) = calls.join_next(), if !calls.is_empty() => record(&mut summary, result?),
            Some(result) = dispatchers.join_next() => {
                result??;
                return Err(Error::Worker);
            }
            index = pacer.receiver.recv(), if summary.attempted < total => {
                let index = index.ok_or(Error::Worker)?;
                calls.spawn(call::originate(
                    clients[index as usize % clients.len()].clone(),
                    plan.clone(), media.clone(), index,
                ));
                summary.attempted += 1;
                summary.peak_concurrent_calls = summary.peak_concurrent_calls.max(calls.len());
            }
        }
    }
    // UAS dialogs have their own ACK/BYE deadlines, so failed UACs cannot strand streams.
    while counters.active_server.load(Ordering::Relaxed) > 0 {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            Some(result) = dispatchers.join_next() => {
                result??;
                return Err(Error::Worker);
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let elapsed = start.elapsed();
    let consumed = cpu::sample()
        .since(&baseline)
        .bucket_starting_with("sipload-");
    let _ = stop_sender.send(true);
    while let Some(result) = dispatchers.join_next().await {
        result??;
    }
    let mut media = Arc::try_unwrap(media).map_err(|_| Error::Worker)?;
    summary.set_media(media.finish()?);
    summary.setup = Percentiles::from(&*counters.setup.lock().map_err(|_| Error::Worker)?);
    summary.bye = Percentiles::from(&*counters.bye.lock().map_err(|_| Error::Worker)?);
    summary.sip_messages_dropped = counters.sip_messages_dropped.snapshot();
    summary.sip_send_errors = counters.sip_send_errors.snapshot();
    summary.sip_retransmissions_sent = counters.retransmitted_sent.load(Ordering::Relaxed);
    summary.sip_retransmissions_received = counters.retransmitted_received.load(Ordering::Relaxed);
    summary.uas_failed_by_reason = counters
        .server_failed_by_reason
        .lock()
        .map_err(|_| Error::Worker)?
        .clone();
    summary.uas_failures = counters.server_failures.load(Ordering::Relaxed);
    summary.active_calls = calls.len() + counters.active_server.load(Ordering::Relaxed);
    summary.pending_transactions = counters.pending_transactions.load(Ordering::Relaxed);
    summary.elapsed_seconds = elapsed.as_secs_f64();
    summary.generator_cpu_cores =
        consumed.total_microseconds() as f64 / 1_000_000.0 / summary.elapsed_seconds;
    Ok(summary)
}
fn record(summary: &mut Summary, result: Result<(), Error>) {
    match result {
        Ok(()) => summary.succeeded += 1,
        Err(error) => {
            summary.failed += 1;
            let reason = match error {
                Error::Status(status) => status.to_string(),
                Error::Timeout => "timeout".into(),
                other => other.to_string(),
            };
            *summary.failed_by_reason.entry(reason).or_default() += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_plan_fails_before_binding() {
        let mut plan = super::super::tests::plan();
        plan.users = 0;
        assert!(run(plan).is_err());
    }
    #[test]
    fn result_accounting_records_status_and_timeout() {
        let mut summary = Summary::default();
        record(&mut summary, Err(Error::Status(503)));
        record(&mut summary, Err(Error::Timeout));
        record(&mut summary, Ok(()));
        assert_eq!(summary.failed_by_reason["503"], 1);
        assert_eq!(summary.failed_by_reason["timeout"], 1);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 2);
    }
}
