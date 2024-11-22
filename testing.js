import { User } from "./models/User.js";
import { Skill } from "./models/Skills.js";
import connectDB from "./db.js";

connectDB();

const userWithSkills = await User.findOne({ name: 'Ramya' }).populate('skills');
console.log(userWithSkills);
