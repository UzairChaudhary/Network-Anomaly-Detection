import axios from 'axios';

const API_URL = 'http://127.0.0.1:5000';

export const collectData = async (duration, interval) => {
  const response = await axios.post(`${API_URL}/collect_data`, { duration, interval });
  return response.data;
};

// export const analyzeData = async (method) => {
//   const response = await axios.post(`${API_URL}/analyze`, { method });
//   return response.data;
// };
export const analyzeData = async () => {
  const response = await axios.get(`${API_URL}/analyze`);
  return response.data;
};
export const DetectAttack = async () => {
  const response = await axios.get(`${API_URL}/detect`);
  return response.data;
};