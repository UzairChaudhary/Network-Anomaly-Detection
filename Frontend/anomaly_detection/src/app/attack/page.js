"use client"
import React, { useState } from 'react';
import { DetectAttack } from '../api/network/route';
import dynamic from 'next/dynamic';

const Plot = dynamic(() => import('react-plotly.js'), { ssr: false });

export default function NetworkAnalysis() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleAnalysis = async () => {
    setLoading(true);
    try {
      const analysisResults = await DetectAttack();
      setResults(analysisResults);
    } catch (error) {
      console.error('Error during analysis:', error);
    }
    setLoading(false);
  };

  const renderPlot = (method, interfaceName, rateType) => {
    if (!results || !results[method] || !results[method][interfaceName]) return null;

    const data = results[method][interfaceName][rateType];
    return (
      <div>
        <h3>{method.toUpperCase()} - {interfaceName} - {rateType}</h3>
        <Plot
          data={[
            {
              y: data.data,
              type: 'scatter',
              mode: 'lines',
              name: rateType,
            },
            {
              x: data.anomalies.map(a => a.index),
              y: data.anomalies.map(a => a.rate_value),
              type: 'scatter',
              mode: 'markers',
              name: 'Anomalies',
              marker: { color: 'red', size: 10 },
            },
          ]}
          layout={{ width: 600, height: 400 }}
        />
      </div>
    );
  };

  const renderPotentialAttacks = () => {
    if (!results || !results.potential_attacks) return null;

    return (
      <div>
        <h2>Potential Attacks Detected</h2>
        {results.potential_attacks.map((attack, index) => (
          <div key={index} className="attack-info">
            <h3>{attack[0]}</h3>
            <p>{attack[1]}</p>
            {attack[0] === "Suspicious Connections" && renderSuspiciousConnections(attack[1])}
          </div>
        ))}
      </div>
    );
  };

  const renderSuspiciousConnections = (details) => {
    let connections;
    if (typeof details === 'string') {
      // If it's a string, try to extract the array part
      const match = details.match(/Unusual connection patterns: (.+)/);
      if (match) {
        try {
          // Replace single quotes with double quotes and parse
          connections = JSON.parse(match[1].replace(/'/g, '"'));
        } catch (error) {
          console.error('Failed to parse suspicious connections:', error);
          return <p>Error parsing suspicious connections data</p>;
        }
      } 
    } else if (Array.isArray(details)) {
      // If it's already an array, use it directly
      connections = details;
    } else {
      console.error('Unexpected format for suspicious connections:', details);
      return <p>Unexpected format for suspicious connections</p>;
    }
  
    return (
      <div>
        {connections.map((conn, index) => (
          <div key={index} className="suspicious-connection">
            <h4>Suspicious Connection: {index + 1}</h4>
            <p>Remote IP: {conn.remote_ip}</p>
            <p>Remote Port: {conn.remote_port}</p>
            <p>PID: {conn.pid}</p>
            <p>Status: {conn.status}</p>
            <p>Connection Count: {conn.count}</p>
            <h5>Process Information:</h5>
            {renderProcessInfo(conn.process_info)}
          </div>
        ))}
      </div>
    );
  };

  const renderProcessInfo = (processInfo) => {
    if (processInfo.error) {
      return <p>Process Info: {processInfo.error}</p>;
    }
  
    return (
      <div>
        <p>Name: {processInfo.name || 'N/A'}</p>
        <p>Executable: {processInfo.exe || 'N/A'}</p>
        <p>Command Line: {processInfo.cmdline ? processInfo.cmdline.join(' ') : 'N/A'}</p>
        <p>Username: {processInfo.username || 'N/A'}</p>
        <p>CPU Usage: {processInfo.cpu_percent ? `${processInfo.cpu_percent}%` : 'N/A'}</p>
        <p>Memory Usage: {processInfo.memory_percent ? `${processInfo.memory_percent}%` : 'N/A'}</p>
        <p>Status: {processInfo.status || 'N/A'}</p>
        <p>Created: {processInfo.create_time || 'N/A'}</p>
        <p>Open Files: {processInfo.open_files ? processInfo.open_files.length : 'N/A'}</p>
        <p>Threads: {processInfo.num_threads || 'N/A'}</p>
        <p>Parent PID: {processInfo.parent || 'N/A'}</p>
        <p>Child PIDs: {processInfo.children ? processInfo.children.join(', ') : 'N/A'}</p>
      </div>
    );
  };

  return (
    <div>
      <h1>Network Analysis</h1>
      <button onClick={handleAnalysis} disabled={loading}>
        {loading ? 'Analyzing...' : 'Start Analysis'}
      </button>
      {renderPotentialAttacks()}
      
    </div>
  );
}