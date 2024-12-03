import { User } from "./models/User.js";
import { Skill } from "./models/Skills.js";
import connectDB from "./db.js";
// import { Skill } from "./models/Skills.js";
import { Request } from "./models/Request.js";
import Counter from "./models/Counter.js";
// import connectDB from "./db.js";

await connectDB();

// const user = await User.findOne({ rollno: "24MX121" }, { _id: 0, skills: 1 });
// const userSkills = user?.skills;
// console.log(userSkills);
// const final = await Request.find(
//   {
//     subjectId: { $in: userSkills },
//     status: "Pending",
//   },
//   {
//     senderId: 1,
//     description: 1,
//     subjectId: 1,
//     _id: 0,
//   }
// );
// console.log(final);

// const final = await Request.find(
//   {
//     senderId: "24MX120",
//     status: "Pending",
//   },
//   {
//     senderId: 1,
//     description: 1,
//     subjectId: 1,
//     _id: 0,
//   }
// );
// console.log(final);

// const skills = await User.aggregate([
//   {
//     $match: {
//       rollno: "24MX125",
//     },
//   },
//   {
//     $unwind: {
//       path: "$skills",
//     },
//   },
//   {
//     $lookup: {
//       from: "skills",
//       localField: "skills",
//       foreignField: "_id",
//       as: "name",
//     },
//   },
//   {
//     $unwind: {
//       path: "$name",
//     },
//   },
//   {
//     $project: {
//       _id: 0,
//       name: ["$name.skill", "$name._id"],
//     },
//   },
// ]);
const skills = await User.aggregate([
  {
    $match: {
      rollno: "24MX125",
    },
  },
  {
    $project: {
      skills: 1,
      _id: 0,
    },
  },
  {
    $lookup: {
      from: "skills",
      localField: "skills",
      foreignField: "_id",
      as: "result",
    },
  },
]);
const missingSkills = await Skill.find({
  _id: { $nin: skills[0].skills },
});

const what = await Skill.find({});
console.log(what);
// skills.forEach((skill) => console.log(skill.name[0]));
