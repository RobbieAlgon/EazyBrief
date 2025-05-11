import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-auth.js";

const firebaseConfig = {
    apiKey: "AIzaSyDoXb68C_gGm33Ni29UohqHy84IpJHZ-Yc",
    authDomain: "brief-generator-5c33f.firebaseapp.com",
    projectId: "brief-generator-5c33f",
    storageBucket: "brief-generator-5c33f.firebasestorage.app",
    messagingSenderId: "810916567820",
    appId: "1:810916567820:web:9f28505921b3d75f7b4729",
    databaseURL:""
  };
  
  const app = initializeApp(firebaseConfig);
  const auth = getAuth(app);
  
  export { auth };
  