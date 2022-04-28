
import {GET_FILELOG} from "../actions/index";
import {GET_GROUPLOG} from "../actions/index";



const initialState = {

    filelog:[],
    grouplog:[]

};

const userlogdata = (state = initialState, action) => {
console.log(action.payload)
    switch (action.type) {

        case GET_FILELOG :
            return {
                ...state,
                filelog:action.payload

            };

        case GET_GROUPLOG :
            return {
                ...state,
                grouplog:action.payload

            };

        default :
            return state;

    }
};

export default userlogdata;