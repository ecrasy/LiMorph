#include "pch.h"
#include "Logging.h"
#include <fstream>

namespace LiMorph {
    class CLogFileOperator
    {
    public:
        void Print(const std::string& msg)
        {
            OutputDebugStringA(msg.c_str());
            OutputDebugStringA("\n");

#ifdef _DEBUG
            if (m_morphLog.is_open())
            {
                m_morphLog << msg;
            }
#endif
        }

        static CLogFileOperator& GetInstance(void)
        {
#ifdef _DEBUG
            static CLogFileOperator s_lfp("D:\\Desktop\\debugfile.txt");
#else
            static CLogFileOperator s_lfg;
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