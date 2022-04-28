import React, {Component} from 'react';
import '../FileUpload.css';
import Modal from 'react-modal';
import {Row,Col,ListGroupItem} from 'react-bootstrap';
import { Route, withRouter } from 'react-router-dom';
import TextField from 'material-ui/TextField';
import * as API from '../api/API';
import {searchFile} from "../actions/index";
import {connect} from 'react-redux';
import {getFiles} from "../actions/index";
import Header from "./Header";

class RightNavBar extends Component {

    state = { isModalOpen: false, filename:'', fileparent:'', isfile:'F' , shareEmail:'', clickSharedFolder:false,  message: ''}


    openModal() {
        this.setState({ isModalOpen: true , fileparent:this.props.parentFile})
    }
    
    handleFileSearch = (event) => {

       
       const searchString =  document.getElementById('mysearch').value;

        

        console.log(searchString);

        API.searchFile(searchString)
        .then((res) => {

            if (res.status == 200) {

                res.json().then(files => {
                            this.props.getFiles(files);
                        });

                        console.log("Success...")
                        this.setState({

                    message: "Search results found"
                });

            }else if (res.status == 401) {
                this.setState({

                    message: "File error"
                });
            }else if (res.status == 500) {
                this.setState({

                    message: "No search results found"
                });
            }
        });
    };

    closeModal(data) {
        console.log(data);

        {data!=""?

            ( data.filename!="" ?(data.shareEmail!=""? this.props.makeSharedFolder(data):this.props.makeFolder(data))
            :''):''}

        this.setState({ isModalOpen: false, clickSharedFolder: false})
    }

    openSharedFolderModal() {
        this.setState({ isModalOpen: true , clickSharedFolder: true})
    }

    style = {
        content : {
            top                   : '50%',
            left                  : '50%',
            right                 : 'auto',
            bottom                : 'auto',
            marginRight           : '-50%',
            transform             : 'translate(-50%, -50%)'
        }
    };

    render(){
console.log(this.props.parentFile)
        return(
       
                

                
        <div className="col-sm-2 sidenav">
            <TextField
type="text"
                    name="mysearch"
                    id="mysearch"
                    
                /> <br/> <br/>
            <button className="btn btn-primary btn-block" type="submit"
                    onClick={this.handleFileSearch}>
                File Search
            </button>
            <br/>
            <div className="text-danger"> </div>
            {this.state.message}
            <br/>
            <Modal isOpen={this.state.isModalOpen} style={this.style} onClose={() => this.closeModal()}>
                <ListGroupItem>
                    <Row className="show-grid">
                        <Col md={4}>FolderName:</Col>
                        <Col md={8}>
                            <input type="text" className="form-control" required="true" autoFocus
                                   onChange={(event) => {
                                       this.setState({
                                           filename: event.target.value
                                       });
                                   }}/>
                        </Col>

                    </Row>
                    <br/>
                    {this.state.clickSharedFolder==true?

                    <Row className="show-grid">
                        <Col md={4}>Share With Email:</Col>
                        <Col md={8}>
                            <input type="email" className="form-control" required="true" placeholder="Enter (;) seperated emails"
                                   onChange={(event) => {
                                       this.setState({
                                           shareEmail: event.target.value
                                       });
                                   }}/>
                        </Col>
                    </Row>:''}
                </ListGroupItem>
                <br/>
                <div className=" row justify-content-md-center">
                    <div className=" col-md-4">
                <button className="btn btn-primary" type="submit"
                        onClick={() => this.closeModal(this.state)}>Save</button>
                    </div>
                    <div className=" col-md-4">
                    <button className="btn btn-primary" type="submit"
                            onClick={() => this.closeModal('')}>Close</button>
                    </div>

                </div>



            </Modal>


        </div>

        )}

}
function mapStateToProps(reducerdata) {
    console.log(reducerdata);

    const filesdata = reducerdata.filesreducer;
    return {filesdata};
}

function mapDispatchToProps(dispatch) {
    return {
        searchFile : (data) => dispatch(searchFile(data)),
        getFiles : (data) => dispatch(getFiles(data))
    };
}

export default withRouter(connect(mapStateToProps, mapDispatchToProps)(RightNavBar));