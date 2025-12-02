/**
 * Authentication Form Component
 * Handles login and registration UI
 */

import React from 'react';
import { AlertCircle, Shield, Key } from 'lucide-react';

export default function AuthForm({ type, formData, setFormData, onSubmit, loading, error, onSwitchView }) {
  return (
    <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-xl shadow-lg border border-gray-100">
      <div className="text-center">
        <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-blue-100 mb-4">
          <Shield className="w-6 h-6 text-blue-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900">
          {type === 'login' ? 'Secure Login' : 'Generate Identity'}
        </h2>
        <p className="mt-2 text-sm text-gray-500">
          {type === 'login' 
            ? 'Authenticate to access your secure vault' 
            : 'Register to generate your unique RSA-2048 Keypair'}
        </p>
      </div>

      {error && (
        <div className="p-3 text-sm text-red-600 bg-red-50 rounded-lg flex items-center gap-2">
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      <form onSubmit={onSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Username</label>
          <input
            type="text"
            required
            className="w-full px-4 py-2 mt-1 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
            value={formData.username}
            onChange={(e) => setFormData({...formData, username: e.target.value})}
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Password</label>
          <input
            type="password"
            required
            className="w-full px-4 py-2 mt-1 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
            value={formData.password}
            onChange={(e) => setFormData({...formData, password: e.target.value})}
          />
        </div>
        
        <button
          type="submit"
          disabled={loading}
          className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2"
        >
          {loading ? "Processing..." : (type === 'login' ? "Sign In" : "Generate Keys & Register")}
          {!loading && type !== 'login' && <Key size={16} />}
        </button>
      </form>

      <div className="text-center text-sm text-gray-500">
        {type === 'login' ? (
          <p>Need an identity? <button onClick={() => onSwitchView('register')} className="text-blue-600 font-medium hover:underline">Create one</button></p>
        ) : (
          <p>Already have keys? <button onClick={() => onSwitchView('login')} className="text-blue-600 font-medium hover:underline">Sign in</button></p>
        )}
      </div>
    </div>
  );
}
