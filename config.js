const CONFIG = {
    development: {
        API_URL: 'http://localhost:3000/api'
    },
    production: {
        API_URL: 'https://TU_BACKEND_EN_RENDER.onrender.com/api' 
    }
};

const ENV = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
    ? 'development' 
    : 'production';

const API_URL = CONFIG[ENV].API_URL;
console.log('🌐 Modo:', ENV, 'API:', API_URL);