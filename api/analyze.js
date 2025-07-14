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

        // --- Construct the Prompt for the AI (now more specific and in Vietnamese) ---
        const promptParts = [
            'Bạn là một chuyên gia phân tích lừa đảo tài chính và an ninh mạng. Nhiệm vụ của bạn là phân tích thông tin do người dùng cung cấp để tìm dấu hiệu lừa đảo qua mạng như phishing, lừa đảo việc làm, lừa đảo đầu tư, hoặc đánh cắp thông tin cá nhân. Hãy tập trung vào các yếu tố như: lời lẽ hối thúc, yêu cầu cung cấp thông tin nhạy cảm, các đường link đáng ngờ, ngữ pháp và chính tả kém, và các lời đề nghị quá tốt để có thể là sự thật. TUYỆT ĐỐI KHÔNG đưa ra lời khuyên về mối quan hệ cá nhân hay phân tích cảm xúc, trừ khi nó liên quan trực tiếp đến một vụ lừa đảo tài chính (ví dụ: lừa đảo tình cảm). Toàn bộ phản hồi của bạn phải bằng tiếng Việt và tuân thủ nghiêm ngặt định dạng JSON đã được yêu cầu.',
            'Đây là thông tin cần phân tích:'
        ];

        if (text) {
            promptParts.push(`Nội dung văn bản: "${text}"`);
        }
        if (url) {
            promptParts.push(`Đường dẫn URL: "${url}"`);
        }
        
        const imageParts = [];
        if (imageBase64) {
            // Assuming the frontend sends a data URL like "data:image/png;base64,..."
            const mimeType = imageBase64.substring(imageBase64.indexOf(":") + 1, imageBase64.indexOf(";"));
            imageParts.push(fileToGenerativePart(imageBase64, mimeType));
            promptParts.push('Một ảnh chụp màn hình cũng được đính kèm để phân tích.');
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
