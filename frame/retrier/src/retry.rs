#[cfg(feature = "std")]
use crate::localstd::future::Future;
#[cfg(feature = "sgx")]
use crate::localstd::{
    boxed::Box,
    string::{String, ToString},
};
use crate::localstd::{fmt, result::Result, thread, time::Duration};
use tracing::warn;

pub struct Retry<I, T, E> {
    name: String,
    tries: usize,
    strategy: I,
    condition: Condition<T, E>,
}

impl<I, T, E> Retry<I, T, E>
where
    I: Iterator<Item = Duration>,
    T: fmt::Debug,
    E: fmt::Debug,
{
    pub fn new(name: impl ToString, tries: usize, strategy: I) -> Self {
        Self {
            name: name.to_string(),
            tries,
            strategy,
            condition: Condition::Always,
        }
    }

    /// Define condition to retry
    pub fn set_condition<F>(mut self, custom: F) -> Self
    where
        F: Fn(&Result<T, E>) -> bool + 'static + Send,
    {
        self.condition = Condition::Custom(Box::new(custom));
        self
    }

    /// Retry a given operation a certain number of times.
    /// The interval depends on the delay strategy.
    pub fn spawn<O>(self, mut operation: O) -> Result<T, E>
    where
        O: FnMut() -> Result<T, E>,
    {
        let mut iterator = self.strategy.take(self.tries).enumerate();
        let condition = self.condition;
        loop {
            let res = operation();
            if condition.should_retry(&res) {
                if let Some((curr_tries, delay)) = iterator.next() {
                    warn!(
                        "The {} operation retries {} times... (result: {:?})",
                        self.name,
                        curr_tries + 1,
                        res
                    );
                    thread::sleep(delay);
                } else {
                    // if it overs the number of retries
                    return res;
                }
            } else {
                return res;
            }
        }
    }

    #[cfg(feature = "std")]
    pub async fn spawn_async<O, R>(self, mut operation: O) -> Result<T, E>
    where
        O: FnMut() -> R,
        R: Future<Output = Result<T, E>>,
    {
        let mut iterator = self.strategy.take(self.tries).enumerate();
        let condition = self.condition;
        loop {
            let res = operation().await;
            if condition.should_retry(&res) {
                if let Some((curr_tries, delay)) = iterator.next() {
                    warn!(
                        "The {} operation retries {} times... (result: {:?})",
                        self.name,
                        curr_tries + 1,
                        res
                    );
                    actix_rt::time::sleep(delay).await;
                } else {
                    // if it overs the number of retries
                    return res;
                }
            } else {
                return res;
            }
        }
    }
}

enum Condition<T, E> {
    Always,
    Custom(Box<dyn Fn(&Result<T, E>) -> bool + Send>),
}

impl<T, E> Condition<T, E> {
    fn should_retry(&self, result: &Result<T, E>) -> bool {
        match *self {
            Condition::Always => true,
            Condition::Custom(ref cond) => cond(result),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    // Ensure the retrier retries 4 times.
    // delay: 10ms
    #[test]
    fn test_fixed_delay_strategy_success() {
        let mut counter = 1..=4;
        let res = Retry::new("test_counter_success", 4, strategy::FixedDelay::new(10))
            .set_condition(|res| match res {
                Ok(_) => false,
                Err(_) => true,
            })
            .spawn(|| match counter.next() {
                Some(c) if c == 4 => Ok(c),
                Some(_) => Err("Not 4"),
                None => Err("Not 4"),
            })
            .unwrap();

        assert_eq!(res, 4);
    }

    // Even if the retrier retries 3 times, the operation should not be successful
    #[test]
    fn test_fixed_delay_strategy_error() {
        let mut counter = 1..=5;
        let res = Retry::new("test_counter_error", 3, strategy::FixedDelay::new(10))
            .set_condition(|res| match res {
                Ok(_) => false,
                Err(_) => true,
            })
            .spawn(|| match counter.next() {
                Some(c) if c == 5 => Ok(c),
                Some(_) => Err("Some: Not 4"),
                None => Err("None: Not 4"),
            });

        assert_eq!(res, Err("Some: Not 4"));
    }
}
