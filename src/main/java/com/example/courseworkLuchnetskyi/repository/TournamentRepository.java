package com.example.courseworkLuchnetskyi.repository;

import com.example.courseworkLuchnetskyi.model.Tournament;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TournamentRepository extends JpaRepository<Tournament, Long> {
}
