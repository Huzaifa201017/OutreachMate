import { Send, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Form } from './Form';
import { PreviewModal } from './PreviewModal';

export default function ContentPage() {

    const [isOpen, setIsOpen] = useState(false);
    const [showPreview, setShowPreview] = useState(false);
    const [previewContent, setPreviewContent] = useState('');

    const formRef = useRef<HTMLDivElement>(null);
    // const shadowRootRef = useRef<ShadowRoot | null>(null);

    const toggleForm = () => setIsOpen(!isOpen);

    useEffect(() => {
        function handleClickOutside(event: MouseEvent) {

            const outsideClick = typeof event.composedPath === 'function' && !event.composedPath().includes(formRef.current!);
            if (outsideClick) {
                setIsOpen(false);
            }
        }

        document.addEventListener('mousedown', handleClickOutside);
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [showPreview]);

    const handlePreview = (content: string) => {
        setPreviewContent(content);
        setShowPreview(true);
    };

    const handleSend = (content: string) => {
        console.log('Sending email:', content);
        setShowPreview(false);
        setIsOpen(false);
    };

    return (
        <div className="fixed bottom-8 right-8 z-50">
            {/* Floating button */}
            <button
                onClick={toggleForm}
                className={`
            bg-blue-500 hover:bg-blue-600 text-white p-4 rounded-full shadow-lg
            transition-all duration-300 ease-in-out
            ${isOpen
                        ? 'opacity-0 scale-90 translate-y-12 pointer-events-none'
                        : 'opacity-100 scale-100 translate-y-0 hover:scale-110'
                    }
          `}
            >
                <Send size={24} />
            </button>

            {/* Form */}
            <div
                ref={formRef}
                className={`
            absolute bottom-0 right-0
            transition-all duration-300 ease-in-out
            ${isOpen
                        ? 'opacity-100 scale-100 translate-y-0'
                        : 'opacity-0 scale-95 translate-y-12 pointer-events-none'
                    }
          `}
            >
                <div className="bg-white rounded-lg shadow-xl w-80">
                    {/* Header */}
                    <div className="flex items-center justify-between w-full p-4 border-b">
                        <h2 className="text-xl font-semibold text-gray-800">
                            Fill Up Recipient Details
                        </h2>
                        <button
                            onClick={toggleForm}
                            className="text-gray-500 hover:text-gray-700 transition-colors duration-200"
                        >
                            <X size={20} />
                        </button>
                    </div>

                    {/* Form content */}
                    <div className="p-4">
                        <Form onPreview={handlePreview} />
                    </div>
                </div>
            </div>

            {/* Preview Modal */}
            {showPreview && (
                <PreviewModal
                    content={previewContent}
                    onClose={() => setShowPreview(false)}
                    onSend={handleSend}
                />
            )}
        </div>
    );

}