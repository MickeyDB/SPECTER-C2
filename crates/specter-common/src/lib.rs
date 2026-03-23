pub mod checkin;
pub mod error;

pub mod proto {
    pub mod specter {
        pub mod v1 {
            tonic::include_proto!("specter.v1");
        }
    }
}
