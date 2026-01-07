import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";

import authRoutes from "./routes/authRoutes.js";
import errorHandler from "./middleware/error.middleware.js";
import { connectDB } from "./config/db.js";

dotenv.config();

const app = express();


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


  //  SECURITY & CORS

app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = [
        "https://printzet.com",
        "https://www.printzet.com",
        "http://localhost:5173",
        "http://localhost:3020",
        "http://localhost:5025",
      ];

      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(helmet());


  //  HEALTH CHECK

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    uptime: process.uptime(),
    timestamp: new Date(),
  });
});


  //  ROUTES

app.use("/api/auth", authRoutes);


  //  ERROR HANDLER 

app.use(errorHandler);
 
  //  START SERVER & CONNECT DB
connectDB();

const PORT = process.env.PORT || 5025;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
