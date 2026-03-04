import { useState } from "react";
import { authAPI, getErrorMessage } from "../services/api";
import toast from "react-hot-toast";
import { Shield, ShieldCheck, X } from "lucide-react";

export default function MFASettings({ user, onUpdate }) {
  const [showSetup, setShowSetup] = useState(false);
  const [qrCode, setQrCode] = useState("");
  const [secret, setSecret] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showDisableModal, setShowDisableModal] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");

  const handleSetupMFA = async () => {
    setIsLoading(true);
    try {
      const response = await authAPI.mfaSetup();
      const { qr_code, secret } = response.data;
      setQrCode(qr_code);
      setSecret(secret);
      setShowSetup(true);
      toast.success("Scan the QR code with Google Authenticator");
    } catch (error) {
      toast.error(getErrorMessage(error));
    } finally {
      setIsLoading(false);
    }
  };

  const handleEnableMFA = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await authAPI.mfaEnable({ code: verificationCode });
      toast.success("MFA enabled successfully!");
      onUpdate(response.data.user);
      // Reset state
      setShowSetup(false);
      setVerificationCode("");
      setQrCode("");
      setSecret("");
    } catch (error) {
      toast.error(getErrorMessage(error));
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisableMFA = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await authAPI.mfaDisable({ password: disablePassword });
      toast.success("MFA disabled successfully");
      onUpdate(response.data.user);
      // Reset state
      setShowDisableModal(false);
      setDisablePassword("");
    } catch (error) {
      toast.error(getErrorMessage(error));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-[#1a1a1a] border border-gray-800 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-600/10 flex items-center justify-center">
            {user?.mfa_enabled ? (
              <ShieldCheck className="w-5 h-5 text-green-500" />
            ) : (
              <Shield className="w-5 h-5 text-gray-400" />
            )}
          </div>
          <div>
            <h3 className="font-semibold">Two-Factor Authentication</h3>
            <p className="text-sm text-gray-400">
              {user?.mfa_enabled ? "Enabled" : "Disabled"}
            </p>
          </div>
        </div>
        <span
          className={`px-3 py-1 rounded-full text-xs font-medium ${
            user?.mfa_enabled
              ? "bg-green-600/10 text-green-500 border border-green-600/30"
              : "bg-gray-600/10 text-gray-400 border border-gray-600/30"
          }`}
        >
          {user?.mfa_enabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      <p className="text-sm text-gray-400 mb-4">
        Add an extra layer of security to your account using Google
        Authenticator app.
      </p>

      {!user?.mfa_enabled ? (
        <button
          onClick={handleSetupMFA}
          disabled={isLoading}
          className="w-full bg-blue-600 text-white py-2.5 px-4 rounded-lg font-medium hover:bg-blue-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? "Setting up..." : "Enable MFA"}
        </button>
      ) : (
        <button
          onClick={() => setShowDisableModal(true)}
          className="w-full bg-red-600/10 text-red-500 border border-red-600/30 py-2.5 px-4 rounded-lg font-medium hover:bg-red-600/20 transition-colors"
        >
          Disable MFA
        </button>
      )}

      {/* MFA Setup Modal */}
      {showSetup && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#1a1a1a] border border-gray-800 rounded-2xl shadow-xl p-6 max-w-md w-full">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Setup MFA</h3>
              <button
                onClick={() => {
                  setShowSetup(false);
                  setVerificationCode("");
                  setQrCode("");
                  setSecret("");
                }}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-gray-400 mb-3">
                  1. Install Google Authenticator on your phone
                </p>
                <p className="text-sm text-gray-400 mb-3">
                  2. Scan this QR code with the app:
                </p>
                <div className="flex justify-center mb-4 bg-white p-4 rounded-lg">
                  <img src={qrCode} alt="QR Code" className="w-48 h-48" />
                </div>
                <p className="text-xs text-gray-500 mb-2">
                  Or enter this code manually:
                </p>
                <div className="bg-[#0a0a0a] border border-gray-800 p-3 rounded-lg text-center font-mono text-sm break-all">
                  {secret}
                </div>
              </div>

              <form onSubmit={handleEnableMFA}>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  3. Enter the 6-digit code from the app:
                </label>
                <input
                  type="text"
                  value={verificationCode}
                  onChange={(e) =>
                    setVerificationCode(
                      e.target.value.replace(/\D/g, "").slice(0, 6),
                    )
                  }
                  className="w-full px-4 py-3 bg-[#0a0a0a] border border-gray-800 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-2xl tracking-widest text-white"
                  placeholder="000000"
                  maxLength={6}
                  required
                  autoFocus
                />

                <button
                  type="submit"
                  disabled={isLoading || verificationCode.length !== 6}
                  className="w-full mt-4 bg-blue-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? "Verifying..." : "Enable MFA"}
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Disable MFA Modal */}
      {showDisableModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#1a1a1a] border border-gray-800 rounded-2xl shadow-xl p-6 max-w-md w-full">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Disable MFA</h3>
              <button
                onClick={() => {
                  setShowDisableModal(false);
                  setDisablePassword("");
                }}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <form onSubmit={handleDisableMFA} className="space-y-4">
              <p className="text-sm text-gray-400">
                Enter your password to disable two-factor authentication:
              </p>

              <input
                type="password"
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                className="w-full px-4 py-3 bg-[#0a0a0a] border border-gray-800 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent text-white"
                placeholder="Enter your password"
                required
                autoFocus
              />

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setShowDisableModal(false);
                    setDisablePassword("");
                  }}
                  className="flex-1 bg-gray-800 text-gray-300 py-3 px-6 rounded-lg font-semibold hover:bg-gray-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="flex-1 bg-red-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-red-700 transition-colors disabled:opacity-50"
                >
                  {isLoading ? "Disabling..." : "Disable"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
