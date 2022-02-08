#include "log.h"

#include <fstream>
#include <iostream>
#include <windows.h>
#include <debugapi.h>

namespace LiMorphLoader {

    const auto morphLogFilePath = "D:\\Desktop\\debugfile.txt";

    class CLogFileOperator
    {
    public:
        void Print(const std::string& msg)
        {
            OutputDebugStringA(msg.c_str());
            OutputDebugStringA("\n");
            std::cout << msg << std::endl;

#ifdef _DEBUG_LOG
            if (m_morphLog.is_open())
            {
                m_morphLog << msg;
            }
#endif
        }

        static CLogFileOperator& GetInstance(void)
        {
#ifdef _DEBUG_LOG
            static CLogFileOperator s_lfp(morphLogFilePath);
#else
            static CLogFileOperator s_lfp;
#endif

            return s_lfp;
        }

    protected:
        CLogFileOperator() {}

        CLogFileOperator(const std::string& logfilePath)
            : m_morphLog(logfilePath, std::ofstream::app)
        {

        }
        ~CLogFileOperator()
        {
            if (m_morphLog.is_open())
            {
                m_morphLog.close();
            }
        }

    private:
        std::ofstream m_morphLog;
    };

    void Logging::Print(const std::string& msg) {
        CLogFileOperator::GetInstance().Print(msg);
    }

} // namespace morph