/*
 * Copyright (C) 2015   Jeremy Chen jeremy_cz@yahoo.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <common_base/CFdbContext.h>
#include <common_base/CFdbSession.h>
#include <common_base/CIntraNameProxy.h>
#include <common_base/CLogProducer.h>
#include <utils/Log.h>
#include <iostream>

// template<> FdbSessionId_t CFdbContext::tSessionContainer::mUniqueEntryAllocator = 0;

std::mutex CFdbContext::mSingletonLock;
CFdbContext *CFdbContext::mInstance = 0;

CFdbContext::CFdbContext()
    : CBaseWorker("FDBus Context")
    , mNameProxy(0)
    , mLogger(0)
    , mEnableNameProxy(true)
    , mEnableLogger(true)
{

}

CFdbContext *CFdbContext::getInstance()
{
    if (!mInstance)
    {
        std::lock_guard<std::mutex> _l(mSingletonLock);
        if (!mInstance)
        {
            mInstance = new CFdbContext();
        }
    }
    return mInstance;
}

bool CFdbContext::start(uint32_t flag)
{
    return CBaseWorker::start(FDB_WORKER_ENABLE_FD_LOOP | flag);
}

bool CFdbContext::init()
{
    return CBaseWorker::init(FDB_WORKER_ENABLE_FD_LOOP);
}

bool CFdbContext::asyncReady()
{
    if (mEnableNameProxy)
    {
        auto name_proxy = new CIntraNameProxy();
        name_proxy->connectToNameServer();
        mNameProxy = name_proxy;
    }
    if (mEnableLogger)
    {
        auto logger = new CLogProducer();
        std::string svc_url;
        logger->getDefaultSvcUrl(svc_url);
        logger->doConnect(svc_url.c_str());
        mLogger = logger;
    }
    return true;
}

bool CFdbContext::destroy()
{
    if (mNameProxy)
    {
        auto name_proxy = mNameProxy;
        mNameProxy = 0;
        name_proxy->enableNsMonitor(false);
        name_proxy->prepareDestroy();
        delete name_proxy;
    }
    if (mLogger)
    {
        auto logger = mLogger;
        mLogger = 0;
        logger->prepareDestroy();
        delete logger;
    }

    if (!mEndpointContainer.getContainer().empty())
    {
        std::cout << "CFdbContext: Unable to destroy context since there are active endpoint!" << std::endl;
        return false;
    }
    if (!mSessionContainer.getContainer().empty())
    {
        std::cout << "CFdbContext: Unable to destroy context since there are active sessions!\n" << std::endl;
        return false;
    }
    exit();
    join();
    delete this;
    return true;
}

CBaseEndpoint *CFdbContext::getEndpoint(FdbEndpointId_t endpoint_id)
{
    CBaseEndpoint *endpoint = 0;
    mEndpointContainer.retrieveEntry(endpoint_id, endpoint);
    return endpoint;
}

void CFdbContext::registerSession(CFdbSession *session)
{
    auto sid = mSessionContainer.allocateEntityId();
    session->sid(sid);
    mSessionContainer.insertEntry(sid, session);
}

CFdbSession *CFdbContext::getSession(FdbSessionId_t session_id)
{
    CFdbSession *session = 0;
    mSessionContainer.retrieveEntry(session_id, session);
    return session;
}

void CFdbContext::unregisterSession(FdbSessionId_t session_id)
{
    CFdbSession *session = 0;
    auto it = mSessionContainer.retrieveEntry(session_id, session);
    if (session)
    {
        mSessionContainer.deleteEntry(it);
    }
}

void CFdbContext::deleteSession(FdbSessionId_t session_id)
{
    CFdbSession *session = 0;
    (void)mSessionContainer.retrieveEntry(session_id, session);
    if (session)
    {
        delete session;
    }
}

void CFdbContext::deleteSession(CFdbSessionContainer *container)
{
    auto &session_tbl = mSessionContainer.getContainer();
    for (auto it = session_tbl.begin(); it != session_tbl.end();)
    {
        CFdbSession *session = it->second;
        ++it;
        if (session->container() == container)
        {
            delete session;
        }
    }
}

FdbEndpointId_t CFdbContext::registerEndpoint(CBaseEndpoint *endpoint)
{
    auto id = endpoint->epid();
    if (!fdbValidFdbId(id))
    {
        id = mEndpointContainer.allocateEntityId();
        endpoint->epid(id);
        mEndpointContainer.insertEntry(id, endpoint);
        endpoint->enableMigrate(true);
    }
    return id;
}

void CFdbContext::unregisterEndpoint(CBaseEndpoint *endpoint)
{
    CBaseEndpoint *self = 0;
    auto it = mEndpointContainer.retrieveEntry(endpoint->epid(), self);
    if (self)
    {
        endpoint->enableMigrate(false);
        endpoint->epid(FDB_INVALID_ID);
        mEndpointContainer.deleteEntry(it);
    }
}

void CFdbContext::findEndpoint(const char *name
                               , std::vector<CBaseEndpoint *> &ep_tbl
                               , bool is_server)
{
    auto &container = mEndpointContainer.getContainer();
    for (auto it = container.begin(); it != container.end(); ++it)
    {
        auto endpoint = it->second;
        auto found = false;

        if (is_server)
        {
            if (endpoint->role() == FDB_OBJECT_ROLE_SERVER)
            {
                found = true;
            }
        }
        else if (endpoint->role() == FDB_OBJECT_ROLE_CLIENT)
        {
            found = true;
        }

        if (!found)
        {
            continue;
        }

        if (!endpoint->nsName().compare(name))
        {
            ep_tbl.push_back(endpoint);
        }
    }
}

CIntraNameProxy *CFdbContext::getNameProxy()
{
    return (mNameProxy && mNameProxy->connected()) ? mNameProxy : 0;
}

void CFdbContext::reconnectOnNsConnected()
{
    auto &container = mEndpointContainer.getContainer();
    for (auto it = container.begin(); it != container.end(); ++it)
    {
        auto endpoint = it->second;
        endpoint->requestServiceAddress();
    }
}

void CFdbContext::enableNameProxy(bool enable)
{
    mEnableNameProxy = enable;
}

void CFdbContext::enableLogger(bool enable)
{
    mEnableLogger = enable;
}

CLogProducer *CFdbContext::getLogger()
{
    return mLogger;
}

// https://blog.csdn.net/jasonchen_gbd/article/details/44044899
// https://cmdlinelinux.blogspot.com/2020/01/i-have-been-chasing-for-toolcompiler.html
// https://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html
// https://gcc.gnu.org/onlinedocs/libstdc++/manual/ext_demangling.html
extern "C" {
    void __attribute__((no_instrument_function)) __cyg_profile_func_enter(void *this_func, void *call_site);
    void __attribute__((no_instrument_function)) __cyg_profile_func_exit(void *this_func, void *call_site);
}

#include <dlfcn.h>
#include <stdio.h>
#include <cxxabi.h>
#include <unistd.h>        //gettid()

static std::string __attribute__((no_instrument_function)) getTimeStr() {
    ;
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    struct tm* ptm = localtime(&tt);
    char date[32] = { 0 };
    snprintf(date, sizeof(date),
            /*"%02d-%02d-"\*/
            "%02d:%02d:%02d.%06ld",
            /*(int)ptm->tm_mon + 1, (int)ptm->tm_mday,*/
            (int)ptm->tm_hour, (int)ptm->tm_min, (int)ptm->tm_sec,
            std::chrono::duration_cast<std::chrono::microseconds>(
                now.time_since_epoch()).count()%1000000);
    return date;
}

void __attribute__((no_instrument_function)) processfnptr (void *this_fn,
                               void *call_site, bool isIn) {
    int     status;
    Dl_info info;
    dladdr(this_fn, &info);
    auto tid = gettid();
    const char* brace = (isIn?"{":"}");
    const std::string dateStr = getTimeStr();

    // https://en.cppreference.com/w/cpp/keyword/thread_local
    // https://murphypei.github.io/blog/2020/02/thread-local
    thread_local int indent = 2;
    if (!isIn) {
        indent -= 2;
    }

    char *realname = abi::__cxa_demangle(info.dli_sname, nullptr, 0, &status);
    if (realname) {
        fprintf(stderr, "|cyg|%s %d%*c%s " \
                "%s\n",
                dateStr.c_str(), tid, indent, ' ', brace,
                realname);
        free(realname);
    } else {
        fprintf(stderr, "|cyg|%s %d%*c%s " \
                "%s %p\n",
                dateStr.c_str(), tid, indent, ' ', brace,
                info.dli_sname, this_fn);
    }

    if (isIn) {
        indent += 2;
    }
}

static std::mutex gCygMutex;
void __attribute__((no_instrument_function)) __cyg_profile_func_enter (void *this_fn,
                               void *call_site) {
    std::lock_guard<decltype(gCygMutex)> _l(gCygMutex);
    processfnptr(this_fn, call_site, true);
}

void __attribute__((no_instrument_function)) __cyg_profile_func_exit  (void *this_fn,
                               void *call_site) {
    std::lock_guard<decltype(gCygMutex)> _l(gCygMutex);
    processfnptr(this_fn, call_site, false);

}