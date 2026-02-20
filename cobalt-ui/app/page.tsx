'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ShieldCheck, FileSearch, ShieldAlert, Cpu, HardDrive, KeyRound, CheckCircle2, ChevronRight, Activity, Database, LockKeyhole } from 'lucide-react'

export default function Home() {
  const [file, setFile] = useState<File | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState<any | null>(null)

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      setAnalyzing(true)

      // Simulate analysis delay
      setTimeout(() => {
        setResult({
          rootHash: "8f4b5e2a9d1c3f7e6b0a8c2d4f5e7a9b1c3d5f7e9a0b2c4d6f8a0b2c4",
          status: "VALID",
          signatureType: "FIPS 140-2 (aws-lc-rs)",
          signer: "AWS KMS (arn:aws:kms:us-east-1:123456789012:key/mrk-abc)",
          fips: true,
          blocks: 142,
          timestamp: new Date().toISOString()
        })
        setAnalyzing(false)
      }, 1500)
    }
  }

  return (
    <main className="flex-1 overflow-y-auto p-8 bg-slate-950">
      <div className="max-w-5xl mx-auto space-y-8">

        {/* Header */}
        <header className="flex items-center justify-between border-b border-slate-800 pb-6">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-indigo-500/10 rounded-xl border border-indigo-500/20">
              <ShieldCheck className="w-8 h-8 text-indigo-400" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-white">Cobalt Audit Tracker</h1>
              <p className="text-slate-400 text-sm">Enterprise Chain of Custody & Compliance</p>
            </div>
          </div>
          <div className="flex items-center space-x-3 text-sm px-4 py-2 bg-emerald-500/10 text-emerald-400 rounded-full border border-emerald-500/20">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>FIPS 140-2 Mode Active</span>
          </div>
        </header>

        {/* Upload Zone */}
        {!result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="border-2 border-dashed border-slate-800 rounded-2xl p-12 text-center hover:border-indigo-500/50 hover:bg-slate-900/50 transition-all cursor-pointer relative"
          >
            <input
              type="file"
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              onChange={handleFileUpload}
            />
            <div className="flex flex-col items-center justify-center space-y-4">
              <div className="p-4 bg-slate-800/50 rounded-full">
                <FileSearch className="w-8 h-8 text-slate-400" />
              </div>
              <div>
                <h3 className="text-lg font-medium text-white mb-1">Select CBC Artifact or Receipt</h3>
                <p className="text-slate-400 max-w-sm mx-auto text-sm">Upload a .cbc file or verification receipt to trace provenance and validate Merkle Tree integrity.</p>
              </div>
              <button className="px-6 py-2.5 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg font-medium transition-colors">
                Browse Files
              </button>
            </div>
          </motion.div>
        )}

        {/* Analysis State */}
        <AnimatePresence>
          {analyzing && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              className="bg-slate-900 rounded-2xl p-8 border border-slate-800 flex flex-col items-center justify-center space-y-6"
            >
              <Activity className="w-12 h-12 text-indigo-500 animate-pulse" />
              <div className="text-center space-y-2">
                <h3 className="text-lg font-medium text-white">Analyzing Cryptographic Proofs</h3>
                <p className="text-slate-400 text-sm">Verifying AES-GCM tags, Merkle Range Proofs, and checking KMS bounds...</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Results */}
        {result && !analyzing && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

              {/* Status Card */}
              <div className="col-span-1 bg-slate-900 rounded-2xl p-6 border border-slate-800 relative overflow-hidden flex flex-col justify-between">
                <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/10 rounded-full blur-3xl -mr-10 -mt-10" />
                <div className="space-y-4 relative z-10">
                  <div className="h-10 w-10 bg-emerald-500/20 rounded-xl flex items-center justify-center border border-emerald-500/30">
                    <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                  </div>
                  <div>
                    <h3 className="text-emerald-400 font-semibold mb-1">Integrity Validated</h3>
                    <p className="text-slate-400 text-sm">The artifact is completely untampered and mathematically verified.</p>
                  </div>
                </div>
                <div className="pt-6 mt-6 border-t border-slate-800 relative z-10">
                  <p className="text-xs text-slate-500 font-mono flex items-center">
                    <HardDrive className="w-3 h-3 mr-2" /> Blocks: {result.blocks} Verified
                  </p>
                </div>
              </div>

              {/* Crypto Profile */}
              <div className="col-span-2 bg-slate-900 rounded-2xl p-6 border border-slate-800 space-y-6">
                <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wide">Cryptographic Assurance</h3>

                <div className="space-y-4">
                  <div className="flex items-start space-x-4">
                    <div className="bg-slate-800 p-2 rounded-lg mt-1"><Cpu className="w-4 h-4 text-indigo-400" /></div>
                    <div>
                      <p className="text-sm text-slate-400">Hash & Signature Algorithm</p>
                      <p className="font-medium text-white">{result.signatureType}</p>
                    </div>
                  </div>

                  <div className="flex items-start space-x-4">
                    <div className="bg-slate-800 p-2 rounded-lg mt-1"><LockKeyhole className="w-4 h-4 text-cyan-400" /></div>
                    <div>
                      <p className="text-sm text-slate-400">Enterprise KMS Integration</p>
                      <p className="font-mono text-xs text-white bg-slate-950 px-2 py-1 rounded inline-block mt-1">{result.signer}</p>
                    </div>
                  </div>

                  <div className="flex items-start space-x-4">
                    <div className="bg-slate-800 p-2 rounded-lg mt-1"><Database className="w-4 h-4 text-amber-400" /></div>
                    <div className="w-full">
                      <p className="text-sm text-slate-400">Merkle Root</p>
                      <p className="font-mono text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-1.5 rounded truncate w-full mt-1">
                        {result.rootHash}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Provenance Graph */}
            <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800">
              <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wide mb-6">Provenance Graph (Chain of Custody)</h3>
              <div className="relative">
                {/* Line connection */}
                <div className="absolute left-[27px] top-10 bottom-10 w-0.5 bg-slate-800" />

                <div className="space-y-8">
                  <div className="flex items-start space-x-6 relative">
                    <div className="w-14 h-14 rounded-full bg-slate-800 border-2 border-slate-700 flex items-center justify-center z-10 shrink-0 shadow-xl">
                      <FileSearch className="w-6 h-6 text-slate-400" />
                    </div>
                    <div className="pt-2">
                      <p className="text-sm text-slate-500 mb-1">Oct 12, 2024</p>
                      <p className="font-medium text-white text-lg">Source Dataset</p>
                      <p className="text-sm text-slate-400 mt-1">Original 500GB payload encoded at origin.</p>
                    </div>
                  </div>

                  <div className="flex items-start space-x-6 relative">
                    <div className="w-14 h-14 rounded-full bg-indigo-500/20 border-2 border-indigo-500 flex items-center justify-center z-10 shrink-0 shadow-[0_0_15px_rgba(99,102,241,0.2)]">
                      <KeyRound className="w-6 h-6 text-indigo-400" />
                    </div>
                    <div className="pt-2">
                      <p className="text-sm text-slate-500 mb-1">Nov 04, 2024</p>
                      <p className="font-medium text-white text-lg flex items-center">
                        Subrange Extract
                        <span className="ml-3 text-xs bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded-full border border-indigo-500/20 uppercase tracking-wide">Receipt Verified</span>
                      </p>
                      <p className="text-sm text-slate-400 mt-1">Blocks 500–1000 extracted. Cryptographically signed by AWS KMS Policy <span className="text-indigo-400 font-mono">legal-redact</span>.</p>
                    </div>
                  </div>

                  <div className="flex items-start space-x-6 relative">
                    <div className="w-14 h-14 rounded-full bg-emerald-500/20 border-2 border-emerald-500 flex items-center justify-center z-10 shrink-0 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
                      <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                    </div>
                    <div className="pt-2">
                      <p className="text-sm text-slate-500 mb-1">Just Now</p>
                      <p className="font-medium text-white text-lg">Current Artifact</p>
                      <p className="text-sm text-slate-400 mt-1">Mathematically verified derivation from Source Dataset.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => setResult(null)}
                className="px-6 py-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg font-medium transition-colors border border-slate-700"
              >
                Audit Another Artifact
              </button>
            </div>
          </motion.div>
        )}
      </div>
    </main>
  )
}
