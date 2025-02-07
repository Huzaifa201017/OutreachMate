import { Send, X } from 'lucide-react';
import { useState } from 'react';
import EmailBuilder from './EmailBuilder';

export default function ContentPage() {

    const [isOpen, setIsOpen] = useState(false);


    // const formRef = useRef<HTMLDivElement>(null);

    // const toggleForm = () => setIsOpen(!isOpen);

    // useEffect(() => {
    //     function handleClickOutside(event: MouseEvent) {

    //         const outsideClick = typeof event.composedPath === 'function' && !event.composedPath().includes(formRef.current!);
    //         if (!showPreview && outsideClick) {
    //             setIsOpen(false);
    //         }
    //     }

    //     document.addEventListener('mousedown', handleClickOutside);
    //     return () => {
    //         document.removeEventListener('mousedown', handleClickOutside);
    //     };
    // }, [showPreview]);



    return (
        <div className="fixed bottom-8 right-8 z-max">
            {/* Floating button */}

            <button
                onClick={() => setIsOpen(true)}
                className="fixed bottom-8 right-8 bg-blue-600 hover:bg-blue-700 text-white p-4 rounded-full shadow-lg transition-transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
            >
                <Send className="w-6 h-6" />
            </button>

            {/* Email Builder Modal */}
            {isOpen && (
                <div className="fixed inset-0 bg-black bg-opacity-50  flex items-center justify-center resetStyles">
                    <div className="bg-white w-full max-w-6xl h-[90vh] rounded-lg shadow-xl flex flex-col">
                        <div className="p-4 border-b flex justify-between items-center">
                            <h2 className="text-xl font-semibold text-gray-900">Email Builder</h2>
                            <button
                                onClick={() => setIsOpen(false)}
                                className="text-gray-500 hover:text-gray-700"
                            >
                                <X className="w-6 h-6" />
                            </button>
                        </div>
                        <EmailBuilder />
                    </div>
                </div>
            )}


        </div>
    );

}