import json
import base64
import os
import tempfile
import pytest
import cbc_py

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), 
    "../../cbc-core/tests/conformance/vectors.json"
)

with open(VECTORS_PATH, "r") as f:
    suite = json.load(f)

@pytest.mark.parametrize("vector", suite["vectors"], ids=[v["id"] for v in suite["vectors"]])
def test_conformance(vector):
    artifact_bytes = base64.b64decode(vector["artifact_base64"])
    
    # cbc_py currently exposes `validate_file` similar to node
    # write to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".cbc") as tmp:
        tmp.write(artifact_bytes)
        tmp_path = tmp.name

    try:
        if vector["type"] == "valid":
            # should not throw, returns True
            assert cbc_py.validate(tmp_path) is True
             
        elif vector["type"] == "invalid":
            threw = False
            err_msg = ""
            try:
                # If the validation fails cleanly it returns False
                # If there's a cryptographic panic, it raises an Exception
                is_valid = cbc_py.validate(tmp_path)
                if not is_valid:
                    threw = True
                    err_msg = "Validation failed" 
            except Exception as e:
                threw = True
                err_msg = str(e)
            
            assert threw is True, f"Expected {vector['id']} to fail validation"
            
            if "expected_error" in vector and vector["expected_error"]:
                # The python bindings might wrap the rust error, or merely fail.
                # Currently making a best effort match.
                assert vector["expected_error"] in err_msg, f"Expected error '{vector['expected_error']}' not found in '{err_msg}'"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
