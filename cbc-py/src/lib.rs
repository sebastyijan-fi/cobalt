use cbc_core::{decoder, BootstrapSegment};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::fs;

#[pyfunction]
fn inspect(path: String) -> PyResult<dict_output::InspectionResult> {
    let data = fs::read(&path)
        .map_err(|e| PyValueError::new_err(format!("Failed to read file: {}", e)))?;

    if data.len() < 64 {
        return Err(PyValueError::new_err("File too small to be a CBC artifact"));
    }

    let mut bs_bytes = [0u8; 64];
    bs_bytes.copy_from_slice(&data[..64]);

    let bs = BootstrapSegment::decode(&bs_bytes)
        .map_err(|e| PyValueError::new_err(format!("Invalid bootstrap: {:?}", e)))?;

    Ok(dict_output::InspectionResult {
        valid_bootstrap: true,
        version: 1,
        hash_suite: format!("{:?}", bs.hash_suite),
        block_count: bs.block_count,
        block_payload_size: bs.block_payload_size,
        families: vec![
            if bs.family_a() { "A" } else { "" },
            if bs.family_b() { "B" } else { "" },
            if bs.family_c() { "C" } else { "" },
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect(),
    })
}

#[pyfunction]
fn validate(path: String) -> PyResult<bool> {
    let data = fs::read(&path)
        .map_err(|e| PyValueError::new_err(format!("Failed to read file: {}", e)))?;
    match decoder::validate(&data) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyValueError::new_err(format!("Validation failed: {:?}", e))),
    }
}

// Helper module to define return types as Python dicts
mod dict_output {
    use super::*;

    #[pyclass]
    pub struct InspectionResult {
        #[pyo3(get)]
        pub valid_bootstrap: bool,
        #[pyo3(get)]
        pub version: u16,
        #[pyo3(get)]
        pub hash_suite: String,
        #[pyo3(get)]
        pub block_count: u32,
        #[pyo3(get)]
        pub block_payload_size: u32,
        #[pyo3(get)]
        pub families: Vec<String>,
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn cbc_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(inspect, m)?)?;
    m.add_function(wrap_pyfunction!(validate, m)?)?;
    m.add_class::<dict_output::InspectionResult>()?;
    Ok(())
}
