import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cors from "cors";
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { OAuth2Client } from 'google-auth-library';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '.env') });
const app = express();
app.use(cors());
app.use(express.json());

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
    console.log("MongoDB connected");
    try {
      await mongoose.connection.collection('users').dropIndex('username_1');
      console.log("Dropped old username index");
    } catch (e) {
    }
  })
  .catch(err => console.log("MongoDB error:", err));

const User = mongoose.model("User", new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  googleId: String,
  authProvider: { type: String, default: 'local' }
}));

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    console.log("Register attempt:", { name, email });

    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "USER_EXISTS" });
    }

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashed });

    console.log("User registered successfully:", email);
    res.json({ message: "REGISTER_SUCCESS" });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "SERVER_ERROR" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "USER_NOT_FOUND" });

    
    if (user.authProvider === 'google') {
      return res.status(400).json({ message: "GOOGLE_ACCOUNT", hint: "Please sign in with Google" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "WRONG_PASSWORD" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ 
      message: "LOGIN_SUCCESS", 
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: "SERVER_ERROR" });
  }
});

app.post("/auth/google", async (req, res) => {
  try {
    const { code, redirectUri } = req.body;
    
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      })
    });
    
    const tokens = await tokenResponse.json();
    
    if (tokens.error) {
      console.error("Token exchange error:", tokens.error);
      return res.status(400).json({ message: "GOOGLE_AUTH_FAILED" });
    }
    
    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    
    const userInfo = await userInfoRes.json();
    const { id: googleId, email, name } = userInfo;
    
    console.log("Google auth attempt:", { email, name });

    let user = await User.findOne({ email });
    
    if (!user) {
      
      user = await User.create({
        name,
        email,
        googleId,
        authProvider: 'google'
      });
      console.log("New Google user created:", email);
    } else if (user.authProvider === 'local') {
      
      user.googleId = googleId;
      user.authProvider = 'google';
      await user.save();
      console.log("Linked Google to existing account:", email);
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({
      message: "LOGIN_SUCCESS",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Google auth error:", error);
    res.status(500).json({ message: "GOOGLE_AUTH_FAILED" });
  }
});

app.get("/profile", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  res.json({ userId: decoded.id });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);
