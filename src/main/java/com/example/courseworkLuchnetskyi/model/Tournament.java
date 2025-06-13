package com.example.courseworkLuchnetskyi.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;
import java.util.List;
import com.example.courseworkLuchnetskyi.model.Match;

@Entity
@Table(name = "tournaments")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Tournament {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private LocalDate startDate;

    private LocalDate endDate;

    private String location;

    @OneToMany(mappedBy = "tournament", cascade = CascadeType.ALL)
    private List<Match> matches;
}
