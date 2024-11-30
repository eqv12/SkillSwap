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
import nodemailer from "nodemailer";
// import { sendEmail } from './mailer.js';
import crypto from "crypto";

const pendingUsers = {};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "anony3938@gmail.com",
    pass: "bbyi yuej ceni huaa",
  },
});

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
const generateToken = (rollno, expiresIn = "15m") => {
  return jwt.sign({ rollno }, "ramya-preethinthran-sharun", { expiresIn });
};

//token authentication middleware
const authenticate = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) {
    return res.redirect("http://localhost:3000/login?message=Invalid+or+missing+token.+Please+login+again.");
  }

  try {
    const decoded = jwt.verify(token, "ramya-preethinthran-sharun");
    req.user = decoded;
    console.log("this is from authenticate req.user");
    console.log(req.user);
    next();
  } catch (err) {
    return res.redirect("http://localhost:3000/login?message=Invalid+or+missing+token.+Please+login+again.");
  }
};

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/dashboard", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/incomingRequests", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "tutoringRequests.html"));
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

  // // let email = `${rollno}@psgtech.ac.in`;
  // let email = "ramyaraja1206@gmail.com";
  // const hashedPassword = await bcrypt.hash(password, 10);

  // const token = crypto.randomBytes(16).toString("hex");
  // pendingUsers[token] = { email, rollno, name, hashedPassword, createdAt: Date.now() };

  // const verificationLink = `http://localhost:3000/verify-email?token=${token}`;

  // console.log(`Verification email sent to ${email} with link: ${verificationLink}`);

  // res.status(200).json({ message: "Check your email to verify your account." });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ rollno: rollno, name: name, password: hashedPassword });
    await newUser.save();
    res.status(200).json({ message: "User registered successfully", status: 200 });
  } catch (error) {
    console.error("Error registering user: ", error);
    res.status(500).json({ message: "Error registering user", status: 500 });
  }
});

app.get("/verify-email", async (req, res) => {
  const { token } = req.query; // Extract token from the URL query

  const userData = pendingUsers[token];
  if (!userData) {
    return res.status(400).json({ message: "Invalid or expired token." });
  }

  const tokenExpiration = 60 * 60 * 1000; // 1 hour in milliseconds
  if (Date.now() - userData.createdAt > tokenExpiration) {
    delete pendingUsers[token]; // Cleanup expired data
    return res.status(400).json({ message: "Token has expired." });
  }

  try {
    const newUser = new User({
      rollno: userData.rollno,
      name: userData.name,
      password: userData.hashedPassword,
    });
    console.log(newUser);
    await newUser.save();

    // Remove user from pendingUsers
    delete pendingUsers[token];

    // res.status(200).json({ message: 'Email verified successfully! Your account is now active.' });
    res.send(`
      <script>
        localStorage.setItem('registrationStatus', 'verified');
        window.close();
      </script>
    `);
  } catch (error) {
    console.error("Error saving user:", error);
    res.status(500).json({ message: "Error verifying email." });
  }
});

app.post("/login", async (req, res) => {
  console.log(req.body);
  const { rollno, password, remember_me } = req.body;
  try {
    const user = await User.findOne({ rollno: rollno });

    if (user && (await bcrypt.compare(password, user.password))) {
      const tokenExpiry = remember_me ? "7d" : "15m";
      const token = generateToken(rollno, tokenExpiry);
      console.log("This is to check the cookie", token); //vulnerabiity do not keep this in the final code if kept ramya's responsibility.
      res.cookie("authToken", token, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        maxAge: remember_me ? 7 * 24 * 60 * 60 * 1000 : null,
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

app.post("/logout", (req, res) => {
  try {
    res.clearCookie("authToken", {
      httpOnly: true,
      sameSite: "strict",
      secure: true,
    });
    res.sendStatus(200);
  } catch (error) {
    console.error("Error clearing cookie:", error);
    res.status(500).send({ error: "Failed to logout" });
  }
});

app.post("/addUserSkill", authenticate, async (req, res) => {
  const { skillid } = req.body;
  const userid = req.user.rollno;
  console.log(skillid);
  try {
    const newUserSkill = await User.findOneAndUpdate({ rollno: userid }, { $addToSet: { skills: skillid } }, { new: true });
    console.log(newUserSkill);
    res.status(200).json(newUserSkill);
  } catch (error) {
    console.error("Error updating skills:", error);
    res.status(500).json({ message: "Error updating skills", error: error.message });
  }
});

app.post("/removeUserSkill", authenticate, async (req, res) => {
  const { skillid } = req.body;
  const userid = req.user.rollno;
  console.log(skillid);
  try {
    const removeUserSkill = await User.findOneAndUpdate({ rollno: userid }, { $pull: { skills: skillid } }, { new: true });
    console.log(removeUserSkill);
    res.status(200).json(removeUserSkill);
  } catch (error) {
    console.error("Error updating skills:", error);
    res.status(500).json({ message: "Error updating skills", error: error.message });
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
  const { subjectId, title, description } = req.body;
  const senderId = req.user.rollno;
  console.log(req.body);
  console.log(senderId, subjectId, title, description);

  try {
    const newRequest = new Request({ senderId: senderId, subjectId: subjectId, title: title, description: description });
    await newRequest.save();
    res.status(201).json({ message: "Request sent successfully", status: 201 });
  } catch (error) {
    console.error("Error creating request ", error);
    res.status(500).json({ message: "Error creating request", status: 500 });
  }
});

app.get("/outgoingRequests", authenticate, (req, res) => {
  res.sendFile(__dirname + "/public/outgoingRequests.html");
});

app.get("/api/outgoingRequests", authenticate, async (req, res) => {
  const requesterId = req.user.rollno;
  try {
    const myReqs = await User.aggregate([
      {
        $lookup: {
          from: "requests",
          localField: "rollno",
          foreignField: "senderId",
          as: "req",
        },
      },
      {
        $unwind: {
          path: "$req",
        },
      },
      {
        $match: {
          rollno: requesterId,
        },
      },
      {
        $addFields: {
          subjId: "$req.subjectId",
          title: "$req.title",
          descr: "$req.description",
          status: "$req.status",
        },
      },
      {
        $lookup: {
          from: "skills",
          localField: "subjId",
          foreignField: "_id",
          as: "sk",
        },
      },
      {
        $addFields: {
          subjName: { $arrayElemAt: ["$sk", 0] },
        },
      },
      {
        $addFields: {
          subjName: "$subjName.skill",
        },
      },
      {
        $unset: ["req", "sk", "password", "_id", "__v", "subjId", "phone", "skills"],
      },
    ]);
    res.json(myReqs);
    // res.render('outgoingRequests', { requests: myReqs });
    console.log(myReqs);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch outgoing requests", status: 500 });
  }
});

app.get("/incomingRequests", authenticate, async (req, res) => {
  const receiverId = req.user.rollno;
  try {
    const myReqs = await User.aggregate();
    res.json(myReqs);
    console.log(myReqs);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch outgoing requests", status: 500 });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
