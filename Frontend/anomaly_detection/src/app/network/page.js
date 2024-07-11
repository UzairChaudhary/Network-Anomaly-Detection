"use client"
import react from 'react';
import { useState } from 'react';
import { collectData, analyzeData } from '../api/network/route';
import dynamic from 'next/dynamic';




const Plot = dynamic(() => import('react-plotly.js'), { ssr: false });

export default function NetworkAnalysis() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleAnalysis = async () => {
    setLoading(true);
    try {
      //const networkData = await collectData(60, 1);  // Collect data for 60 seconds with 1-second interval
      const analysisResults = await analyzeData();
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
        <h4>Anomalies:</h4>
        <ul>
          {data.anomalies.map((anomaly, index) => (
            <li key={index}>
              Index: {anomaly.index}, Rate: {anomaly.rate_value}
              <h5>Process Information:</h5>
              {anomaly.process_info.length > 0 ? (
                <ul>
                  {anomaly.process_info.map((proc, pIndex) => (
                    <li key={pIndex}>
                      <strong>PID:</strong> {proc.pid}<br />
                      <strong>Name:</strong> {proc.name}<br />
                      <strong>Username:</strong> {proc.username}<br />
                      {/* <strong>Executable:</strong> {proc.exe}<br /> */}
                      <strong>Status:</strong> {proc.status}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No relevant process information found for this anomaly.</p>
              )}
            </li>
          ))}
        </ul>
      </div>
    );
  };

  return (
    <div>
      <h1>Network Analysis</h1>
      <button onClick={handleAnalysis} disabled={loading}>
        {loading ? 'Analyzing...' : 'Start Analysis'}
      </button>
      {results && Object.keys(results['z-score']).map(interfaceName => (
        <div key={interfaceName}>
          <h2>{interfaceName}</h2>
          <div style={{ display: 'flex', flexWrap: 'wrap' }}>
            {['bytes_sent_rate', 'bytes_recv_rate', 'packets_sent_rate', 'packets_recv_rate'].map(rateType => (
              <div key={rateType} style={{ display: 'flex' }}>
                {renderPlot('z-score', interfaceName, rateType)}
                {renderPlot('isolation-forest', interfaceName, rateType)}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}