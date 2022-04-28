import {ADDFILE, INC_SHARECOUNT,SEARCH_FILE} from "../actions/index";
import {DELETE_FILE} from "../actions/index";
import {GET_FILES} from "../actions/index";
import {MARK_STAR} from "../actions/index";



const initialState = {

    files :[]
};

const filedata = (state = initialState, action) => {

    switch (action.type) {


        case ADDFILE :
            return {
                files:[
                    ...state.files,
                    action.payload
                ]
            }
            
        case SEARCH_FILE :
            return {
                files:[
                    ...state.files,
                    action.payload
                ]
            }


        case GET_FILES :
            return {
                files:action.payload

            }
        case DELETE_FILE :
            return {
                files:[
                    ...state.files.slice(0, action.payload),
                    ...state.files.slice(action.payload + 1)
                ]
            }

        case MARK_STAR :

            var newfiles=state.files;

            newfiles[action.index].starred=action.payload;

            return {
                files:newfiles


            }

        case INC_SHARECOUNT :

            var newfiles=state.files;
            console.log(action)

            newfiles[action.index].sharedcount=action.payload;

            return {
                files:newfiles
            }


        default :
            return state;

    }
};

export default filedata;