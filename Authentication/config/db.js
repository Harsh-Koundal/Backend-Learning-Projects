import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

export const connectDB = async()=>{
    try{

        mongoose
        .connect(process.env.DB_URI)
        .then(async()=>{
            console.log("MongoDB Connected");
        })
        
    }catch(err){

        console.log("MongoDB Error:",err.message);
        process.exit(1);   

    }
}