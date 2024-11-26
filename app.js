import express, { json, urlencoded } from "express";
import { connect } from "mongoose";
import { User } from "./models/User.js";
// import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import { Skill } from "./models/Skills.js";
import { Request } from "./models/Request.js";
import Counter from "./models/Counter.js";
import connectDB from "./db.js";
import { getNextSequence } from "./utilities/getNextSequence.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;
connectDB();
// const dbURI =
//   "mongodb+srv://ramya:Wimmss123.@dev-skill-swap-cluster.efbjn.mongodb.net/skillSwap?retryWrites=true&w=majority&appName=dev-skill-swap-cluster";

// connect(dbURI)
//   .then(() => console.log("Connected to MongoDB"))
//   .catch((err) => console.error("MongoDB connection error", err));

app.use(express.static("public"));
app.use(cookieParser());

// app.use(cors());
app.use(json());
app.use(urlencoded({ extended: true }));

//these are the middlewares.
const generateToken = (rollno) => {
  return jwt.sign({ rollno }, "ramya-preethinthran-sharun", { expiresIn: "15m" });
};

//token authentication middle where this is
const authenticate = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) {
    return res.status(401).json({ message: "Token not found. Authentication failed. Sign in again" });
  }

  try {
    const decoded = jwt.verify(token, "ramya-preethinthran-sharun");
    req.user = decoded;
    console.log("this is from authenticate req.user");
    console.log(req.user);
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired token. Please sign in again" });
  }
};

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.get("/newRequest", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "addrequest.html"));
});

app.get("/listSkills", async (req, res) => {
  try {
    const skills = await Skill.find({});
    res.json(skills);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch skills", status: 500 });
  }
});

app.post("/register", async (req, res) => {
  const { rollno, name, password } = req.body;
  console.log(rollno, name, password);

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ rollno: rollno, name: name, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully", status: 201 });
  } catch (error) {
    console.error("Error registering user: ", error);
    res.status(500).json({ message: "Error registering user", status: 500 });
  }
});

app.post("/login", async (req, res) => {
  console.log(req.body);
  const { rollno, password } = req.body;
  try {
    const user = await User.findOne({ rollno: rollno });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = generateToken(rollno);
      res.cookie("authToken", token, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
      });
      res.status(200).json({ message: "User credentials authenticated", status: 200 });
    } else {
      res.status(401).json({ message: "Bad credentials", status: 401 });
    }
  } catch (error) {
    console.error("Error during login: ", error);
    res.status(500).send("Error logging in");
  }
});

app.post("/addSkill", async (req, res) => {
  const { skill } = req.body;
  console.log(req.body);
  console.log(skill);
  console.log(req.body.skill);

  try {
    const nextId = await getNextSequence("skills");
    const newSubject = new Skill({ _id: nextId, skill: skill });
    await newSubject.save();
    res.status(201).json({ message: "Subject registered successfully", status: 201 });
  } catch (error) {
    console.error("Error registering Subject: ", error);
    await Counter.findOneAndUpdate(
      { id: "skills" },
      { $inc: { seq: -1 } } // Decrement the counter
    );
    res.status(500).json({ message: "Error registering Subject", status: 500 });
  }
});

app.post("/newRequest", authenticate, async (req, res) => {
  const { subjectId, description } = req.body;
  const senderId = req.user.rollno;
  console.log(req.body);
  console.log(senderId, subjectId, description);

  try {
    const newRequest = new Request({ senderId: senderId, subjectId: subjectId, description: description });
    await newRequest.save();
    res.status(201).json({ message: "Request sent successfully", status: 201 });
  } catch (error) {
    console.error("Error creating request ", error);
    res.status(500).json({ message: "Error creating request", status: 500 });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
