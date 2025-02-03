import { useState } from 'react';
import { X, Send } from 'lucide-react';

interface PreviewModalProps {
    content: string;
    onClose: () => void;
    onSend: (content: string) => void;
}

export function PreviewModal({ content: initialContent, onClose, onSend }: PreviewModalProps) {
    const [editedContent, setEditedContent] = useState(initialContent);

    const handleSend = () => {
        onSend(editedContent);
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg shadow-xl w-[600px] max-w-[90vw] max-h-[90vh] overflow-y-auto">
                <div className="p-6">
                    <div className="flex justify-between items-center mb-4">
                        <h2 className="text-xl font-semibold text-gray-800">Preview & Edit Email</h2>
                        <button
                            onClick={onClose}
                            className="text-gray-500 hover:text-gray-700"
                        >
                            <X size={20} />
                        </button>
                    </div>
                    <textarea
                        value={editedContent}
                        onChange={(e) => setEditedContent(e.target.value)}
                        className="w-full h-64 bg-gray-50 p-4 rounded-lg mb-4 resize-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                    <div className="flex justify-end space-x-4">
                        <button
                            onClick={onClose}
                            className="px-4 py-2 text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleSend}
                            className="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors flex items-center space-x-2"
                        >
                            <Send size={16} />
                            <span>Send Email</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}