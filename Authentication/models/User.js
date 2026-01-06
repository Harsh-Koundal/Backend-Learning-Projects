import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true,
    },

    password: {
        type: String,
        required: true,
        minlength: 8,
        select: false,
    },

    role: {
        type: String,
        enum: ["USER", "ADMIN"],
        default: "USER",
    },

    refreshToken: {
        type: String,
        select: false,
    },
},
    { timestamps: true },
);


userSchema.pre("save", async function (next) {
    // Only hash if password is new or modified
    if (!this.isModified("password")) return next();

    const SALT_ROUNDS = 12; // industry recommended
    this.password = await bcrypt.hash(this.password, SALT_ROUNDS);

    next();
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

export default mongoose.model("User", userSchema)