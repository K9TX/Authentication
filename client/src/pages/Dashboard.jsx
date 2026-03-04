import { useAuthStore } from "../stores/authStore";
import { useNavigate } from "react-router-dom";
import MFASettings from "../components/MFASettings";
import { LogOut, Shield, Calendar } from "lucide-react";

function Dashboard() {
  const { user, logout, updateUser } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "numeric",
      day: "numeric",
      year: "numeric",
    });
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-2xl font-bold">
              {user?.username?.charAt(0).toUpperCase()}
            </div>
            <div>
              <h1 className="text-2xl font-bold">Welcome, {user?.username}!</h1>
              <p className="text-gray-400 text-sm flex items-center gap-1">
                <Calendar className="w-4 h-4" />
                Member since {formatDate(user?.created_at)}
              </p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 px-4 py-2 bg-red-600/10 text-red-500 border border-red-600/30 rounded-lg hover:bg-red-600/20 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>

        {/* Account Information */}
        <div className="bg-[#1a1a1a] border border-gray-800 rounded-xl p-6 mb-6">
          <div className="flex items-center gap-2 mb-6">
            <Shield className="w-5 h-5 text-blue-500" />
            <h2 className="text-lg font-semibold">Account Information</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="text-sm text-gray-400 flex items-center gap-1 mb-2">
                Username
              </label>
              <p className="text-white font-medium">{user?.username}</p>
            </div>

            <div>
              <label className="text-sm text-gray-400 flex items-center gap-1 mb-2">
                Email
              </label>
              <p className="text-white font-medium truncate">{user?.email}</p>
            </div>

            <div>
              <label className="text-sm text-gray-400 flex items-center gap-1 mb-2">
                Full Name
              </label>
              <p className="text-white font-medium">
                {user?.first_name && user?.last_name
                  ? `${user.first_name} ${user.last_name}`
                  : "Not set"}
              </p>
            </div>

            <div>
              <label className="text-sm text-gray-400 flex items-center gap-1 mb-2">
                Status
              </label>
              <div className="flex items-center gap-2">
                <span className="inline-block w-2 h-2 bg-green-500 rounded-full"></span>
                <span className="text-green-500 font-medium">Verified</span>
              </div>
            </div>
          </div>
        </div>

        {/* MFA Settings */}
        <MFASettings user={user} onUpdate={updateUser} />
      </div>
    </div>
  );
}

export default Dashboard;
