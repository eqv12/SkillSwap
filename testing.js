import { User } from "./models/User.js";
import { Skill } from "./models/Skills.js";
import connectDB from "./db.js";
// import { Skill } from "./models/Skills.js";
import { Request } from "./models/Request.js";
import Counter from "./models/Counter.js";
// import connectDB from "./db.js";

await connectDB();

const test = await User.findOne({ rollno: "24MX121" });
console.log(test);
const user = await User.findOne({ rollno: "24MX121" }, { _id: 0, skills: 1 });
const userSkills = user?.skills;
console.log(userSkills);
const final = await Request.find(
  {
    subjectId: { $in: userSkills },
    status: "Pending",
  },
  {
    senderId: 1,
    description: 1,
    subjectId: 1,
    _id: 0,
  }
);
console.log(final);
