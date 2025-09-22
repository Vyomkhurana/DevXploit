import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import dotenv from "dotenv";

dotenv.config();


const app = express();
app.get("/", async(req,res)=>{
    res.send("Hello");
})

app.listen(3000, async()=>{
    console.log("Running on Port 3000!");
})