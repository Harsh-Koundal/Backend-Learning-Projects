import express from 'express';
import dotenv from 'dotenv';

import { connectDB } from './config/db.js';

dotenv.config();

const app = express();

app.use(express.json());

connectDB();
const PORT = process.env.PORT || 5025;
app.listen(PORT,()=>{
    console.log(`Server running on port ${PORT}`);
});