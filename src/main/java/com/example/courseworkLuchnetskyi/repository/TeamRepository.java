package com.example.courseworkLuchnetskyi.repository;

import com.example.courseworkLuchnetskyi.model.Team;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TeamRepository extends JpaRepository<Team, Long> {
}
