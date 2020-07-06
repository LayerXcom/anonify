#[macro_export]
macro_rules! impl_memory {
    ( $( $t:tt )* ) => {
        $crate::__impl_inner_memory!(@normalize $( $t )* );
    };
}

#[macro_export]
macro_rules! __impl_inner_memory {
    (@normalize
        $( ($id:expr, $name:expr, Address => $value:ty) ),*
    ) => {
        $crate::__impl_inner_memory!(@normalize $( ($id, $name, $value) ),* );
    };

    (@normalize
        $( ($id:expr, $name:expr, $value:ty) ),*
    ) => {
        $crate::__impl_inner_memory!(@imp $( ($id, $name, $value) ),* );
    };

    (@imp
        $( ($id:expr, $name:expr, $value:ty) ),*
    ) => {
        #[derive(Debug, Clone)]
        pub struct MemName;

        impl MemNameConverter for MemName {
            fn as_id(name: &str) -> MemId {
                match name {
                    $( $name => MemId::from_raw($id), )*
                    _ => panic!("invalid mem name"),
                }
            }
        }

        /// Return maximum size of mem values
        fn max_size() -> usize {
            *[ $( <$value>::default().size(), )* ]
                .into_iter()
                .max()
                .expect("Iterator should not be empty.")
        }
    };
}

#[macro_export]
macro_rules! impl_runtime {
    (
        $( $t:tt )*
    ) => {
        $crate::__impl_inner_runtime!(@imp
            $($t)*
        );
    };
}

#[macro_export]
macro_rules! __impl_inner_runtime {
    (@imp
        $(
            #[fn_id=$fn_id:expr]
            pub fn $fn_name:ident(
                $runtime:ident,
                $sender:ident : $address:ty
                $(, $param_name:ident : $param:ty )*
            ) {
                $( $impl:tt )*
            }
        )*
    ) => {
        $(
            #[derive(Encode, Decode, Debug, Clone, Default)]
            #[allow(non_camel_case_types)]
            pub struct $fn_name {
                $( pub $param_name: $param, )*
            }
        )*

        #[derive(Debug, Clone)]
        pub struct CallName;

        impl CallNameConverter for CallName {
            fn as_id(name: &str) -> u32 {
                match name {
                    $( stringify!($fn_name) => $fn_id, )*
                    _ => panic!("invalid call name"),
                }
            }
        }

        #[derive(Debug, Clone, Encode, Decode)]
        pub enum CallKind {
            $(
                #[allow(non_camel_case_types)]
                $fn_name($fn_name),
            )*
        }

        impl<G: ContextOps<S>, S: State> CallKindExecutor<G, S> for CallKind {
            type R = Runtime<G, S>;

            fn new(id: u32, state: &mut [u8]) -> Result<Self> {
                match id {
                    $( $fn_id => Ok(CallKind::$fn_name($fn_name::from_bytes(state)?)), )*
                    _ => return Err(anyhow!("Invalid Call ID")),
                }
            }

            fn execute(self, runtime: Self::R, my_addr: UserAddress) -> Result<Vec<UpdatedState<S>>> {
                match self {
                    $( CallKind::$fn_name($fn_name) => {
                        runtime.$fn_name(
                            my_addr,
                            $( $fn_name.$param_name, )*
                        )
                    }, )*
                    _ => unimplemented!()
                }
            }
        }

        pub struct Runtime<G: ContextOps<S>, S: State> {
            db: G,
            phamtom: PhantomData<S>,
        }

        impl<G: ContextOps<S>, S: State> RuntimeExecutor<G, S> for Runtime<G, S> {
            type C = CallKind;

            fn new(db: G) -> Self {
                Runtime {
                    db,
                    phamtom: PhantomData,
                }
            }

            fn execute(self, kind: Self::C, my_addr: UserAddress) -> Result<Vec<UpdatedState<S>>> {
                kind.execute(self, my_addr)
            }
        }

        impl<G: ContextOps<S>, S: State> Runtime<G, S> {
            pub fn get_map<SN: State>(
                &self,
                key: UserAddress,
                name: &str
            ) -> Result<SN> {
                let mem_id = MemName::as_id(name);
                let mut tmp = self.db.get_state(key, mem_id).as_bytes();
                SN::from_bytes(&mut tmp)
            }

            pub fn get(&self, name: &str) -> S {
                let mem_id = MemName::as_id(name);
                self.db.get_state(name, mem_id)
            }

            $(
                pub fn $fn_name (
                    $runtime,
                    $sender: $address
                    $(, $param_name : $param )*
                ) -> Result<Vec<UpdatedState<S>>> {
                    $( $impl )*
                }
            )*
        }
    };
}

#[macro_export]
macro_rules! update {
    ($addr:expr, $mem_name:expr, $value:expr) => {
        UpdatedState::new($addr, MemName::as_id($mem_name), $value)?
    };

    ($mem_name:expr, $value:expr) => {
        UpdatedState::new($mem_name, MemName::as_id($mem_name), $value)?
    };
}

#[macro_export]
macro_rules! insert {
    ( $($update:expr),* ) => {
        Ok(vec![$( $update),* ])
    };
}
