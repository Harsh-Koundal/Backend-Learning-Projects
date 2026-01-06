import jwt from "jsonwebtoken";

const authMiddleware = (req,res,next)=>{
    const authHeader = req.headers.authorization;

    if(!authHeader || !authHeader.startsWith("Bearer ")){
        return res.status(401).json({message: "Unauthorized"});
    }

    const token =  authHeader.split(" ")[1];

    try{
        const decoded = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        next();
    }catch(err){
        return res.status(401).json({message: "Unauthorized"});
    }
};
export default authMiddleware;