import mongoose from "mongoose";
const { Schema } = mongoose;

const requestSchema = new Schema({
    senderId: { type: String, required: true, ref: 'User',},
    subject: { type: String,ref: 'Skill', required: true },
    status: { type: String, enum: ['Pending', 'Accepted', 'Rejected'], default: 'Pending' },
    rejectedBy: [{type: Schema.Types.ObjectId, ref: 'User'}]
});

const Request = mongoose.model("Request", requestSchema);
export { Request };
