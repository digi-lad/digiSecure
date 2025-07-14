/**
 * This is the backend serverless function with a live connection to the Gemini API.
 * File path: /api/analyze.js
 *
 * It receives data from the frontend, constructs a detailed prompt in Vietnamese, sends it to the Gemini API,
 * and then forwards the AI's structured response back to the frontend.
 */

// We need to import the Google Generative AI SDK.
// In your Vercel project, you'll need to add `@google/generative-ai` to your package.json dependencies.
import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from "@google/generative-ai";

// Initialize the AI model
// The API key is securely accessed from Vercel's environment variables.
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ 
    model: "gemini-1.5-flash",
    // We define a strict JSON schema for the AI's response to ensure consistency.
    // Descriptions are now in Vietnamese to guide the model.
    generationConfig: {
        responseMimeType: "application/json",
        temperature: 0.2, // Lower temperature for more consistent, less "creative" results.
        responseSchema: {
            type: "OBJECT",
            properties: {
                verdict: { 
                    type: "STRING", 
                    enum: ["SCAM", "NOT A SCAM", "UNCERTAIN"],
                    description: "Phán quyết cuối cùng: 'SCAM' (Lừa đảo), 'NOT A SCAM' (Không phải lừa đảo), hoặc 'UNCERTAIN' (Không chắc chắn)."
                },
                confidence: { 
                    type: "NUMBER",
                    description: "Mức độ tự tin của phán quyết, là một số nguyên từ 0 đến 100." // Instructing for an integer 0-100
                },
                reason: { 
                    type: "STRING",
                    description: "Giải thích ngắn gọn, bằng tiếng Việt, cho phán quyết của bạn."
                },
                red_flags: { 
                    type: "ARRAY", 
                    items: { type: "STRING" },
                    description: "Một danh sách các dấu hiệu đáng ngờ (red flags) được phát hiện, viết bằng tiếng Việt."
                },
                advice: { 
                    type: "STRING",
                    description: "Lời khuyên cụ thể cho người dùng nên làm gì tiếp theo, viết bằng tiếng Việt."
                }
            },
            required: ["verdict", "confidence", "reason", "advice"]
        }
    }
});

// These settings are to prevent the model from blocking responses due to the content of the scams themselves.
const safetySettings = [
    { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE },
];


// Helper function to convert Base64 image data to a format the API understands
function fileToGenerativePart(base64Data, mimeType) {
    return {
        inlineData: {
            data: base64Data.split(',')[1], // Remove the "data:image/jpeg;base64," prefix
            mimeType
        },
    };
}


// The main handler for the serverless function
export default async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', ['POST']);
        return res.status(405).end(`Method ${req.method} Not Allowed`);
    }

    try {
        const { text, url, imageBase64 } = req.body;

        if (!text && !url && !imageBase64) {
            return res.status(400).json({ error: 'No content provided for analysis.' });
        }

        // --- Construct the Prompt for the AI (in English for better accuracy, requesting Vietnamese output) ---
        const promptParts = [
            `You are an expert financial and cybersecurity scam analyst. Your task is to analyze information provided by a user to find signs of online scams like phishing, job scams, investment fraud, or information theft. Focus on elements like: urgent language, requests for sensitive information, suspicious links, poor grammar and spelling, and offers that are too good to be true.`,
            `IMPORTANT: Do NOT give advice on personal relationships or emotional analysis, unless it is directly part of a financial scam (e.g., a romance scam asking for money).`,
            `CRITICAL: If the provided text or image is ambiguous or lacks clear scam indicators, you MUST lower your confidence score significantly. If there is not enough context to make a judgment, you MUST use the "UNCERTAIN" verdict. Do not be overconfident.`,
            `Your entire final response MUST be in Vietnamese and strictly follow the required JSON format.`,
            '---',
            'Here is the information to analyze:'
        ];

        if (text) {
            promptParts.push(`Pasted Text: "${text}"`);
        }
        if (url) {
            promptParts.push(`URL provided: "${url}"`);
        }
        
        const imageParts = [];
        if (imageBase64) {
            // Assuming the frontend sends a data URL like "data:image/png;base64,..."
            const mimeType = imageBase64.substring(imageBase64.indexOf(":") + 1, imageBase64.indexOf(";"));
            imageParts.push(fileToGenerativePart(imageBase64, mimeType));
            promptParts.push('A screenshot is also attached for analysis.');
        }

        const fullPrompt = promptParts.join('\n\n');

        // --- Call the Gemini API ---
        const result = await model.generateContent([fullPrompt, ...imageParts], { safetySettings });
        
        // The response from the model is already a JSON object because of our schema definition.
        const aiResponse = result.response.candidates[0].content.parts[0].text;
        
        // Send the AI's structured response back to the frontend.
        res.status(200).json(JSON.parse(aiResponse));

    } catch (error) {
        console.error('Error in analysis function:', error);
        res.status(500).json({ 
            verdict: 'ERROR',
            confidence: 100,
            reason: 'Đã xảy ra lỗi khi giao tiếp với AI. Điều này có thể do sự cố cấu hình hoặc dữ liệu đầu vào không hợp lệ.',
            red_flags: ['Lỗi API'],
            advice: 'Vui lòng kiểm tra nhật ký máy chủ để biết thêm chi tiết. Đảm bảo khóa API của bạn được định cấu hình chính xác trong các biến môi trường của Vercel.'
         });
    }
}
