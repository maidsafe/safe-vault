// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![cfg_attr(feature="clippy", allow(print_stdout))]

use time::SteadyTime;

pub struct TestGroup {
    name: Option<String>,
    case: Option<String>,
    test_case_timestamp: SteadyTime,
    test_group_timestamp: SteadyTime,
}

impl TestGroup {
    pub fn new(name: &str) -> TestGroup {
        println!("{} ...", name);
        TestGroup {
            name: Some(name.to_owned()),
            case: None,
            test_case_timestamp: SteadyTime::now(),
            test_group_timestamp: SteadyTime::now(),
        }
    }

    pub fn start_case(&mut self, case: &str) {
        if let Some(ref case) = self.case {
            let duration = SteadyTime::now() - self.test_case_timestamp;
            println!("    {} ... ok , completed in {:?}", case, duration);
        }
        println!("    {} ...", case);
        self.test_case_timestamp = SteadyTime::now();
        self.case = Some(case.to_owned());
    }

    pub fn release(&mut self) {
        if let Some(ref case) = self.case {
            let duration = SteadyTime::now() - self.test_case_timestamp;
            println!("    {} ... ok , completed in {:?}", case, duration);
        }
        if let Some(ref name) = self.name {
            let duration = SteadyTime::now() - self.test_group_timestamp;
            println!("{} ... ok , completed in {:?}\n", name, duration);
        }
        self.case = None;
        self.name = None;
    }
}

impl Drop for TestGroup {
    fn drop(&mut self) {
        if let Some(ref case) = self.case {
            let duration = SteadyTime::now() - self.test_case_timestamp;
            println!("    {} ... FAILED after {:?}", case, duration);
        }
        if let Some(ref name) = self.name {
            println!("{} ... FAILED\n", name);
        }
    }
}
