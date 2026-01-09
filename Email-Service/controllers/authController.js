import jwt from "jsonwebtoken";
import crypto from "crypto";
import { User } from "../models/User.js";
import sendEmail from "../utils/sendEmail.js";
import { success } from "zod";

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

const generateResetToken = ()=>{
    const token = crypto.randomBytes(32).toString("hex");
    const hashed = crypto.createHash("sha256").update(token).digest("hex");
    return {token,hashed};
};

// Controllers 

// Email Verification
export const generateEmailVerificationToken = () => {
    const token = crypto.randomBytes(32).toString("hex");

    const hashedToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

    return { token, hashedToken };
};

// Register
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

        const { token, hashedToken } = generateEmailVerificationToken();

        const user = await User.create({
            name,
            email,
            password,
            emailVerificationToken: hashedToken,
            emailVerificationExpires: Date.now() + 15 * 60 * 1000,
        });

        const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

        await sendEmail({
            to: user.email,
            subject: "Verify your email",
            html: `
        <h2>Email Verification</h2>
        <p>Click the link below to verify your email:</p>
        <a href="${verifyUrl}">Verify Email</a>
        <p>This link expires in 15 minutes.</p>
      `,
        });

        res.status(201).json({
            success: true,
            message: "Registration successful. Please verify your email.User registered successfully",
            user,
        });
    } catch (err) {
        next(err);
    };
};

// Verify Email
export const verifyEmail = async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) {
            return res.status(400).json({ message: "Invalid token" });
        }

        const hashedToken = crypto
            .create("sha256")
            .update(token)
            .digest("hex")

        const user = await User.findOne({
            emailVerificationToken: hashedToken,
            emailVerificationExpires: { $gt: Date.now() },
        }).select("+emailVerificationToken");

        if (!user) {
            return res.status(400).json({ message: "Token expired or invalid" });
        }

        user.emailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;

        await user.save();

        res.json({
            success: true,
            message: "Email verified successfully",
        });
    } catch (err) {
        res.status(500).json({ message: "Email verification failed" });
    }
};


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

        if (!user.emailVerified) {
            return res.status(403).json({
                message: "Please verify your email before logging in",
            });
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
};


// Refresh Token
export const refresh = async (req, res, next) => {
    try {
        const token = req.cookies.refreshToken;

        if (!token) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);

        const hashedToken = hashToken(token);

        const user = await User.findId(decoded.userId).select("+refreshToken");

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
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.status(200).json({
            success: true,
            accessToken: newAccessToken,
        });
    } catch (err) {
        next(err);
    }
};


// Logout 
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

// Forgot Password

export const forgotPassword = async(req,res,next)=>{
    try{
        const {email} = req.body;
        if(!email){
            return res.status(400).json({message:"Email is required"});
        }

        const user = await User.findOne({email});

        if(!user) return res.status(404).json({message:"Email does not exists"});

        const {token,hashed} = generateResetToken();

        user.passwordResetToken = hashed;
        user.passwordResetExpires = Date.now() + 15 *60*1000; // 15 min
        await user.save();

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

        await sendEmail({
            to:user.email,
            subject:"Reset your password",
            html:`
            <h2>Password Reset</h2>
            <p>Click the link to reset your passowrd:</p>
            <a href = "${resetUrl}">Reset Password</a>
            <p>This link expires in 15 minutes.</p>
            `,
        })

        res.json({success:true,message:"Reset link was sent to your email"});
    }catch(err){
        next(err);
    }
}

export const resetPassword = async(req,res,next)=>{
    try{
        const {token,password} = req.body;

        if(!token || !password) return res.status(400).json({message:"Invalid request"});

        const hashed = crypto.createHash("sha256").update(token).digest("hex");

        const user = await User.findOne({
            passwordResetToken:hashed,
            passwordResetExpires: {$gt: Date.now()},
        }).select("+passwordResetToken");

        if(!user) return res.status(400).json({message:"Token is invalid or expired"});

        user.password = password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        user.refreshToken = undefined;

        await user.save();

        res.status(200).json({message:"Password reset successful"});
    }catch(err){
        next(err);
    }
};