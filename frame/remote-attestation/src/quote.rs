use crate::client::*;
use crate::error::{FrameRAError, Result};
use frame_types::UntrustedStatus;
use http_req::uri::Uri;
use sgx_types::*;
use std::string::String;
use std::vec::Vec;

extern "C" {
    fn ocall_sgx_init_quote(
        retval: *mut UntrustedStatus,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;

    fn ocall_get_quote(
        retval: *mut UntrustedStatus,
        p_sigrl: *const u8,
        sigrl_len: u32,
        report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_spid: *const sgx_spid_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut sgx_quote_t,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

/// The very high level service for remote attestations
/// Use base64-encoded QUOTE structure to communicate via defined API.
pub struct Quote {
    base64_quote: String,
}

impl Quote {
    pub fn new(base64_quote: String) -> Self {
        Self { base64_quote }
    }

    pub fn remote_attestation(
        &self,
        uri: &str,
        ias_api_key: &str,
    ) -> Result<(AttestationReport, ReportSig)> {
        let uri: Uri = uri.parse().expect("Invalid uri");
        let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", &self.base64_quote);
        let mut writer = Vec::new();

        let response = RAClient::new(&uri)
            .ias_apikey_header_mut(ias_api_key)
            .quote_body_mut(&body.as_bytes())
            .send(&mut writer)?;

        let ra_resp = RAResponse::from_response(writer, response)?.verify_attestation_report()?;

        Ok((ra_resp.attestation_report, ra_resp.report_sig))
    }
}

#[derive(Clone, Copy, Default)]
pub struct QuoteTarget {
    target_info: sgx_target_info_t,
    enclave_report: Option<sgx_report_t>,
}

impl QuoteTarget {
    /// Returns information required by an Intel® SGX application to get a quote of one of its enclaves.
    pub fn new() -> Result<Self> {
        let mut rt = UntrustedStatus::default();
        let mut target_info = sgx_target_info_t::default();
        let mut gid = sgx_epid_group_id_t::default();

        let status = unsafe {
            ocall_sgx_init_quote(
                &mut rt as *mut UntrustedStatus,
                &mut target_info as *mut sgx_target_info_t,
                &mut gid as *mut sgx_epid_group_id_t,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(FrameRAError::OcallError {
                status,
                function: "ocall_sgx_init_quote",
            });
        }
        if rt.is_err() {
            return Err(FrameRAError::UntrustedError {
                status: rt,
                function: "ocall_sgx_init_quote",
            });
        }

        Ok(Self {
            target_info,
            enclave_report: None,
        })
    }

    pub fn set_enclave_report(mut self, report_data: &sgx_report_data_t) -> Result<Self> {
        let enclave_report =
            sgx_tse::rsgx_create_report(&self.target_info, &report_data).map_err(|err| {
                FrameRAError::OcallError {
                    status: err,
                    function: "sgx_tse::rsgx_create_report",
                }
            })?;
        self.enclave_report = Some(enclave_report);
        Ok(self)
    }

    /// Create quote with attestation key ID and enclave's local report.
    pub fn create_quote(self, spid: &sgx_spid_t) -> Result<Quote> {
        const RET_QUOTE_BUF_LEN: u32 = 2048;
        let mut rt = UntrustedStatus::default();
        let mut quote = vec![0u8; RET_QUOTE_BUF_LEN as usize];
        let mut quote_len: u32 = 0;

        let status = unsafe {
            ocall_get_quote(
                &mut rt as *mut UntrustedStatus,
                std::ptr::null(),                                     // p_sigrl
                0,                                                    // sigrl_len
                &self.enclave_report.unwrap() as *const sgx_report_t, // enclave_report must be set
                sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,      // quote_type
                spid as *const sgx_spid_t,                            // p_spid
                std::ptr::null(),                                     // p_nonce
                std::ptr::null_mut(),                                 // p_qe_report
                quote.as_mut_ptr() as *mut sgx_quote_t,
                RET_QUOTE_BUF_LEN, // maxlen
                &mut quote_len as *mut u32,
            )
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(FrameRAError::OcallError {
                status,
                function: "ocall_sgx_get_quote",
            });
        }
        if rt.is_err() {
            return Err(FrameRAError::UntrustedError {
                status: rt,
                function: "ocall_sgx_get_quote",
            });
        }

        let _ = quote.split_off(quote_len as usize);
        Ok(Quote::new(base64::encode(&quote)))
    }
}
