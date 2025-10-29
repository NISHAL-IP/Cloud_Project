import React, { useState } from "react";

// Example data for widgets and cards
const stats = [
  { label: "Active Users", value: 1280, icon: "👥" },
  { label: "Alerts Today", value: 23, icon: "🚨" },
  { label: "Devices Online", value: 42, icon: "💡" },
  { label: "Pending Tasks", value: 7, icon: "📝" },
];

const recentAlerts = [
  { id: 1, title: "Temperature High", time: "2 min ago", status: "critical" },
  { id: 2, title: "Door Opened", time: "10 min ago", status: "warning" },
  { id: 3, title: "System Check", time: "30 min ago", status: "info" },
];

export default function ModernDashboard() {
  const [showModal, setShowModal] = useState(false);

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4 md:p-8">
      {/* Header */}
      <header className="flex flex-col md:flex-row items-center justify-between mb-8">
        <h1 className="text-3xl font-bold text-indigo-700 mb-2 md:mb-0 transition-all duration-300 hover:tracking-wider">
          🚀 Modern Dashboard
        </h1>
        <button
          className="px-5 py-2 bg-indigo-600 text-white rounded-lg shadow hover:bg-indigo-700 transition-all duration-200"
          onClick={() => setShowModal(true)}
        >
          + New Alert
        </button>
      </header>

      {/* Stats Widgets */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {stats.map((stat, idx) => (
          <div
            key={stat.label}
            className="bg-white rounded-xl shadow-lg p-6 flex items-center space-x-4 transform hover:scale-105 transition-transform duration-300 cursor-pointer group"
          >
            <span className="text-3xl">{stat.icon}</span>
            <div>
              <div className="text-2xl font-semibold text-indigo-700 group-hover:text-indigo-900 transition-colors duration-200">
                {stat.value}
              </div>
              <div className="text-gray-500">{stat.label}</div>
            </div>
          </div>
        ))}
      </section>

      {/* Recent Alerts Card */}
      <section className="bg-white rounded-2xl shadow-xl p-6 mb-8 transition-shadow hover:shadow-2xl duration-300">
        <h2 className="text-xl font-bold text-indigo-700 mb-4">Recent Alerts</h2>
        <ul>
          {recentAlerts.map((alert) => (
            <li
              key={alert.id}
              className={`flex items-center justify-between py-2 px-2 rounded-lg mb-2 transition-colors duration-200 ${
                alert.status === "critical"
                  ? "bg-red-50 hover:bg-red-100"
                  : alert.status === "warning"
                  ? "bg-yellow-50 hover:bg-yellow-100"
                  : "bg-blue-50 hover:bg-blue-100"
              }`}
            >
              <span className="font-medium">{alert.title}</span>
              <span className="text-xs text-gray-500">{alert.time}</span>
              <span
                className={`ml-2 px-2 py-1 rounded text-xs font-semibold ${
                  alert.status === "critical"
                    ? "bg-red-500 text-white"
                    : alert.status === "warning"
                    ? "bg-yellow-400 text-white"
                    : "bg-blue-400 text-white"
                }`}
              >
                {alert.status}
              </span>
            </li>
          ))}
        </ul>
      </section>

      {/* Modal Example */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 transition-all">
          <div className="bg-white rounded-xl shadow-2xl p-8 w-full max-w-md animate-fadeIn">
            <h3 className="text-lg font-bold mb-4 text-indigo-700">Create New Alert</h3>
            <input
              className="w-full border border-indigo-200 rounded px-3 py-2 mb-4 focus:outline-none focus:ring-2 focus:ring-indigo-400 transition"
              placeholder="Alert Title"
            />
            <div className="flex justify-end space-x-2">
              <button
                className="px-4 py-2 bg-gray-200 rounded hover:bg-gray-300 transition"
                onClick={() => setShowModal(false)}
              >
                Cancel
              </button>
              <button className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 transition">
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// This component demonstrates a modern, reactive UI with Tailwind CSS, responsive layout, animated cards, modal, and interactive elements.
