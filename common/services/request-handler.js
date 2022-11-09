import axios from 'axios';

let allow = true;
let currentid = 0;
const cancelToken = axios.CancelToken
const source = cancelToken.source();


export const disableRequests = () => {
    allow = false;
    source.cancel('Requests cancelled');
    return;
}

export const initializeInterceptor = (core) => {
    core.http.intercept({
        responseError: (httpErrorResponse, controller) => {
            if (
                httpErrorResponse.response?.status === 401
            ) {
                disableRequests();
                setTimeout(() => window.location.reload(), 1000);
            }
        },
    });
}

export const request = async (options = '') => {
    if (!allow) {
        return Promise.reject('Requests are disabled');
    }
    if (!options.method | !options.url) {
        return Promise.reject("Missing parameters")
    }
    const requestId = currentid;
    currentid++;

    options = {...options,cancelToken: source.token, validateStatus: function (status) {
    return (status >= 200 && status < 300) || status === 401;
  },}
    if (allow) {
        try {
            const requestData = await axios(options);
            if(requestData.status === 401){
                if(requestData.data.message === 'Unauthorized'){
                    disableRequests();
                }
                throw new Error(requestData.data)
            }
            return Promise.resolve(requestData);
        }
        catch (e) {
            return Promise.reject(e);
        }
    }
}
