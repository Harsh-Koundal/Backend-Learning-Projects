import jwt from "jsonwebtoken";
import crypto from "crypto";
import User from "../models/User.js";

// Helpers

const generateAccessToken = (user) => {
    return jwt.sign(
        { userId: user._id, role: user.role },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
    );
};

const generateRefreshToken = (user) => {
    return jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
    );
};

const hashToken = (token) => {
    return crypto.createHash("sha256").update(token).digest("hex");
}

// CONTROLLERS

// Register User

export const register = async (req, res, next) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }
        const user = await User.create({ name, email, password });

        res.status(201).json({
            success: true,
            message: "User registered successfully",
            user,
        });
    } catch (err) {
        next(err);
    };
}

// Login User

export const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }
        const user = await User.findOne({ email }).select("+password +refreshToken");

        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshToken = hashToken(refreshToken);
        await user.save();

         res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.status(200).json({
            success: true,
            message: "Login successful",
            accessToken,
            user,
        });

    } catch (err) {
        next(err);
    }
}


// Refresh Token

export const refresh = async (req, res, next) => {
    try {
        const token = req.cookies.refreshToken;

        if (!token) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);

        const hashedToken = hashToken(token);

        const user = await User.findById(decoded.userId).select("+refreshToken");

        if (!user || user.refreshToken !== hashedToken) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        user.refreshToken = hashToken(newRefreshToken);
        await user.save();

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.status(200).json({
            success: true,
            accessToken: newAccessToken,
        });

    } catch (err) {
        next(err);
    }
};

// Logout User

export const logout = async (req, res, next) => {
    try {
        const token = req.cookies.refreshToken;
        if (token) {
            const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
            const user = await User.findById(decoded.userId).select("+refreshToken");

            if (user) {
                user.refreshToken = null;
                await user.save();
            }
        }
        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Strict",
        });
        res.status(200).json({
            success: true,
            message: "Logged out successfully",
        });
    } catch (err) {
        next(err);
    }
};