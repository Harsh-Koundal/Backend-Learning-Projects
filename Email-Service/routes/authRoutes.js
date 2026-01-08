import express from "express";
import {
  register,
  login,
  refresh,
  logout,
  verifyEmail,
} from "../controllers/authController.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", logout);
router.get("/verify-emil",verifyEmail);

export default router;
