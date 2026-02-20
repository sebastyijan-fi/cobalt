--------------------------- MODULE cbc_protocol ---------------------------
EXTENDS Naturals, Sequences, FiniteSets

(* 
    Formal Specification of the Cobalt (CBC) Context-Bound Container Protocol.
    This model focuses on the structural integrity (Family A) and the state
    machine of a CBC decoder.
*)

CONSTANTS 
    HashSuites,      \* Set of supported hash algorithms
    MaxBlocks        \* Bound for model checking

VARIABLES 
    artifact_state,  \* Current state of the artifact (Bootstrap, Blocks, Footer)
    chain_commitment, \* The current rolling hash value
    verified_blocks,  \* Number of blocks verified so far
    error_raised      \* System error flag

(* Possible states for the decoder *)
States == {"START", "BOOTSTRAP_VERIFIED", "BLOCKS_VERIFYING", "FOOTER_VERIFIED", "ERROR"}

TypeOK == 
    /\ artifact_state \in States
    /\ verified_blocks \in 0..MaxBlocks
    /\ error_raised \in {TRUE, FALSE}

(* Invariant: A successful decode must mean all blocks match the chain *)
IntegrityInvariant == 
    (artifact_state = "FOOTER_VERIFIED") => (verified_blocks > 0)

Init == 
    /\ artifact_state = "START"
    /\ chain_commitment = "C0" \* Symbolic initial value
    /\ verified_blocks = 0
    /\ error_raised = FALSE

(* Step 1: Verify Bootstrap *)
VerifyBootstrap == 
    /\ artifact_state = "START"
    /\ \/ /\ artifact_state' = "BOOTSTRAP_VERIFIED"
          /\ UNCHANGED <<chain_commitment, verified_blocks, error_raised>>
       \/ /\ artifact_state' = "ERROR"
          /\ error_raised' = TRUE
          /\ UNCHANGED <<chain_commitment, verified_blocks>>

(* Step 2: Verify a Block *)
VerifyNextBlock == 
    /\ artifact_state \in {"BOOTSTRAP_VERIFIED", "BLOCKS_VERIFYING"}
    /\ verified_blocks < MaxBlocks
    /\ \/ /\ artifact_state' = "BLOCKS_VERIFYING"
          /\ verified_blocks' = verified_blocks + 1
          /\ chain_commitment' = "Ci" \* Rolling hash update
          /\ UNCHANGED <<error_raised>>
       \/ /\ artifact_state' = "ERROR"
          /\ error_raised' = TRUE
          /\ UNCHANGED <<chain_commitment, verified_blocks>>

(* Step 3: Verify Footer *)
VerifyFooter == 
    /\ artifact_state = "BLOCKS_VERIFYING"
    /\ verified_blocks > 0
    /\ \/ /\ artifact_state' = "FOOTER_VERIFIED"
          /\ UNCHANGED <<chain_commitment, verified_blocks, error_raised>>
       \/ /\ artifact_state' = "ERROR"
          /\ error_raised' = TRUE
          /\ UNCHANGED <<chain_commitment, verified_blocks>>

Next == 
    \/ VerifyBootstrap
    \/ VerifyNextBlock
    \/ VerifyFooter

Spec == Init /\ [][Next]_<<artifact_state, chain_commitment, verified_blocks, error_raised>>

-----------------------------------------------------------------------------
THEOREM Spec => [](TypeOK /\ IntegrityInvariant)
=============================================================================
