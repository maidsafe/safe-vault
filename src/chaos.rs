/// Run code when a chaotic. Defaults to 20% of the time. Overall frequence can be set via "SAFE_CHAOS_LEVEL" env var.
#[macro_export]
macro_rules! with_chaos {
    ( $x:expr) => {{
        #[cfg(feature = "chaos")]
        {
            use log::{debug, warn};
            use rand::distributions::{Distribution, Uniform};
            use std::env;

            let mut rng = rand::thread_rng();
            // 20% chance of happening
            let chaos_trigger: usize = env::var("SAFE_CHAOS_LEVEL")
                .unwrap_or("20".to_string())
                .parse()
                .unwrap();
            let die = Uniform::from(1..100);
            let throw = die.sample(&mut rng);
            debug!(
                "Threshold for \"chaos\" to occur is > {}, we rolled: {}",
                chaos_trigger, throw
            );

            if throw <= chaos_trigger {
                // do the chaos
                warn!("Chaos!");
                $x
            }
        }
    }};
}
