#[macro_export]
macro_rules! trans_tuple_struct {
    ($ts:ident($m:ty)$(, $e:meta),*) => {
        $(#[$e])*
        #[repr(transparent)]
        struct $ts($m);
        impl core::ops::Deref for $ts {
            type Target = $m;

            fn deref(self: &'_ Self) -> &'_ Self::Target {
                &self.0
            }
        }
        impl From<$m> for $ts {
            fn from(arg: $m) -> Self {
                $ts(arg)
            }
        }
        impl Into<$m> for $ts {
            fn into(self: $ts) -> $m {
                self.0
            }
        }
        impl AsRef<$m> for $ts {
            fn as_ref<'a>(&'a self) -> &'a $m {
                &self.0
            }
        }
    };
    (pub $ts:ident($m:ty)$(, $e:meta),*) => {
        $(#[$e])*
        #[repr(transparent)]
        pub struct $ts($m);
        impl core::ops::Deref for $ts {
            type Target = $m;

            fn deref(self: &'_ Self) -> &'_ Self::Target {
                &self.0
            }
        }
        impl From<$m> for $ts {
            fn from(arg: $m) -> Self {
                $ts(arg)
            }
        }
        impl AsRef<$m> for $ts {
            fn as_ref<'a>(&'a self) -> &'a $m {
                &self.0
            }
        }
    };
}
