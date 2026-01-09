import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true,
        unique:true,
    },
    password:{
        type:String,
        required:true,
        minlength:3,
        select:false,
    },
    role:{
        type:String,
        enum:["USER","ADMIN"],
        default:"USER",
    },
    refreshToken:{
        type:String,
        select:false,
    },
    emailVerified:{
        type:Boolean,
        default:false,
    },
    emailVerificationToken:{
        type:String,
        select:false,
    },
    emailVerificationExpires:{
        type:Date,
    },
        passwordResetToken:{
        type:String,
        select:false,
    },
    passwordResetExpires:Date,
},
{timestamps:true},
);

userSchema.pre("save", async function () {
    // Only hash if password is new or modified
    if(!this.isModified("password")) return;

    const SALT_ROUNDS = 12;
    this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
});


// COMPARE PASSWORD METHOD
userSchema.methods.comparePassword = async function (enteredPassword) {
    return bcrypt.compare(enteredPassword, this.password);
};

// REMOVE SENSITIVE FIELDS FROM JSON OUTPUT
userSchema.methods.toJSON = function () {
    const user = this.toObject();
    delete user.password;
    delete user.refreshToken;
    return user;
};

export const User = mongoose.model("User", userSchema);